"""The check engine: plans checks per VM and runs them with retries.

:meth:`CheckEngine.run` is a boundary: it never raises. Each attempt is
bounded by ``spec.timeout_s``; a failing (or agent-erroring) check is retried
every ``retry_interval_s`` until ``spec.wait_s`` has elapsed. The raw
:class:`~pbv.checks._common.Outcome` of the last attempt is mapped to a
:class:`~pbv.core.Status` using ``spec.critical`` (check failures and agent
errors only: internal errors and interrupts are always ERROR).
"""

from __future__ import annotations

import functools
import itertools
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from pbv.checks import linux, scripts, windows
from pbv.checks._common import (
    RETRYABLE,
    Attempt,
    Kind,
    Outcome,
    one_line,
    timeout_message,
    truncate_detail,
)
from pbv.checks.discovery import DISCOVERY_ERROR_TYPE, discover
from pbv.core import (
    ApiError,
    CheckContext,
    CheckResult,
    CheckSpec,
    GuestAgent,
    GuestAgentError,
    OsFamily,
    PbvError,
    PbvTimeoutError,
    Status,
    VmTarget,
)

log = logging.getLogger("pbv.checks")

# Types whose guest commands depend on the OS: SKIPPED when the OS is unknown.
OS_SPECIFIC_TYPES = frozenset({"systemd", "windows_service", "log_scan", "tcp_listen", "http", "script"})
# Types that only exist on one OS even if a hand-built spec lacks only_os.
TYPE_OS = {"systemd": OsFamily.LINUX, "log_scan": OsFamily.LINUX, "windows_service": OsFamily.WINDOWS}


class CheckEngine:
    """Implements :class:`pbv.core.CheckSuite` (SPEC §5)."""

    def __init__(
        self,
        config_dir: Path,
        global_checks: Sequence[CheckSpec] = (),
        *,
        host_env: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        retry_interval_s: float = 3.0,
        should_stop: Callable[[], bool] = lambda: False,
        run_host: scripts.RunHost | None = None,
        discovery_timeout_s: float = 60.0,
    ) -> None:
        self.config_dir = Path(config_dir)
        self.global_checks = tuple(global_checks)
        self.host_env = dict(host_env or {})
        self.sleep = sleep
        self.clock = clock
        self.retry_interval_s = retry_interval_s
        self.should_stop = should_stop
        self.run_host: scripts.RunHost = run_host or functools.partial(
            scripts.default_run_host, grace_s=scripts.HOST_GRACE_S
        )
        self.discovery_timeout_s = discovery_timeout_s
        self.warnings: list[str] = []
        self._script_counter = itertools.count(1)

    # ── plan ───────────────────────────────────────────────────────────────────

    def plan(self, target: VmTarget, guest: GuestAgent, os: OsFamily) -> list[CheckSpec]:
        """Checks for ``target`` in order, de-duplicated by name (first wins).

        manual: target.checks + global; auto: discovered + global (target.checks
        ignored with a warning); hybrid: target.checks + discovered + global.
        OS filtering happens in :meth:`run` (SKIPPED) so the report shows it.
        """
        self.warnings = []
        explicit = list(target.checks)
        discovered: list[CheckSpec] = []
        if target.mode == "auto" and explicit:
            self.warnings.append(
                f"vm {target.vmid}: mode auto ignores {len(explicit)} configured check(s); use mode hybrid to run them"
            )
            explicit = []
        if target.mode in ("auto", "hybrid"):
            discovered = discover(guest, os, timeout_s=self.discovery_timeout_s)
            if not discovered:
                self.warnings.append(f"vm {target.vmid}: discovery found no known services")
        elif target.mode != "manual":
            self.warnings.append(f"vm {target.vmid}: unknown mode {target.mode!r}; treating as manual")
        out: list[CheckSpec] = []
        seen: set[str] = set()
        for spec in [*explicit, *discovered, *self.global_checks]:
            if spec.name in seen:
                continue
            seen.add(spec.name)
            out.append(spec)
        return out

    # ── run ────────────────────────────────────────────────────────────────────

    def run(self, spec: CheckSpec, guest: GuestAgent, ctx: CheckContext) -> CheckResult:
        """Run ``spec`` with retries; never raises."""
        start = self.clock()
        attempts = 0
        try:
            skip = self._skip_reason(spec, ctx.os)
            if skip:
                outcome = Outcome(Kind.SKIP, skip)
            else:
                while True:
                    attempts += 1
                    outcome = self._attempt(spec, guest, ctx)
                    if outcome.kind not in RETRYABLE:
                        break
                    if self.clock() - start >= spec.wait_s or self.should_stop():
                        break
                    log.debug("CHECK_RETRY name=%s attempt=%d summary=%s", spec.name, attempts, outcome.summary)
                    self.sleep(self.retry_interval_s)
        except Exception as exc:  # boundary: run() never raises
            log.debug("CHECK_INTERNAL_ERROR name=%s", spec.name, exc_info=True)
            outcome = Outcome(Kind.ERROR, f"INTERNAL_ERROR: {type(exc).__name__}: {exc}")
        result = self._result(spec, outcome, attempts, self.clock() - start)
        log.info(
            "CHECK_%s name=%s type=%s vmid=%s attempts=%d dur=%.1fs | %s",
            result.status.value.upper(),
            spec.name,
            spec.type,
            ctx.temp_vmid,
            attempts,
            result.duration_s,
            result.summary,
        )
        return result

    @staticmethod
    def _skip_reason(spec: CheckSpec, os: OsFamily) -> str:
        only = spec.only_os or TYPE_OS.get(spec.type)
        if only is not None:
            if os is OsFamily.UNKNOWN:
                return f"OS unknown; check runs only on {only.value}"
            if os is not only:
                return f"only on {only.value} (guest is {os.value})"
        if os is OsFamily.UNKNOWN and spec.type in OS_SPECIFIC_TYPES:
            return "OS unknown; cannot choose guest commands"
        return ""

    def _attempt(self, spec: CheckSpec, guest: GuestAgent, ctx: CheckContext) -> Outcome:
        att = Attempt(spec, ctx, guest, self.clock, self.clock() + spec.timeout_s)
        try:
            return self._dispatch(att)
        except PbvTimeoutError as exc:
            return Outcome(Kind.FAIL, str(exc) or timeout_message(spec.timeout_s))
        except (GuestAgentError, ApiError) as exc:
            return Outcome(Kind.AGENT_ERROR, f"GUEST_AGENT_ERROR: {exc}")
        except PbvError as exc:  # ConfigError, or InterruptedRun raised by an orchestrator guest wrapper
            return Outcome(Kind.ERROR, f"{exc.code}: {exc}")

    def _dispatch(self, att: Attempt) -> Outcome:
        spec, os = att.spec, att.ctx.os
        t = spec.type
        win = os is OsFamily.WINDOWS
        if t == DISCOVERY_ERROR_TYPE:
            return Outcome(Kind.WARN, f"service discovery failed: {spec.params.get('error', '')}")
        if t == "systemd":
            return linux.check_systemd(att)
        if t == "log_scan":
            return linux.check_log_scan(att)
        if t == "windows_service":
            return windows.check_service(att)
        if t == "tcp_listen":
            return windows.check_tcp_listen(att) if win else linux.check_tcp_listen(att)
        if t == "http":
            return windows.check_http(att) if win else linux.check_http(att)
        if t == "command":
            return scripts.check_command(att)
        if t == "script":
            return scripts.check_script(att, n=next(self._script_counter), config_dir=self.config_dir)
        if t == "host_script":
            return scripts.check_host_script(
                att, config_dir=self.config_dir, host_env=self.host_env, run_host=self.run_host
            )
        return Outcome(Kind.ERROR, f"CONFIG_ERROR: unknown check type {t!r}")

    @staticmethod
    def _result(spec: CheckSpec, outcome: Outcome, attempts: int, duration: float) -> CheckResult:
        k = outcome.kind
        if k is Kind.PASS:
            status = Status.PASS
        elif k is Kind.SKIP:
            status = Status.SKIPPED
        elif k is Kind.WARN:
            status = Status.WARN
        elif k is Kind.FAIL:
            status = Status.FAIL if spec.critical else Status.WARN
        elif k is Kind.AGENT_ERROR:
            status = Status.ERROR if spec.critical else Status.WARN
        else:  # ERROR (config/internal problem, InterruptedRun) is never downgraded
            status = Status.ERROR
        return CheckResult(
            name=spec.name,
            type=spec.type,
            status=status,
            summary=one_line(outcome.summary),
            detail=truncate_detail(outcome.detail),
            duration_s=round(max(0.0, duration), 3),
            attempts=attempts,
            critical=spec.critical,
            source=spec.source,
        )
