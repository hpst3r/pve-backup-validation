"""The run loop: preflight, leftover sweep, per-VM lifecycle, cleanup (SPEC §2, §4, §10).

:class:`Runner` restores, boots, checks and destroys one VM at a time. Every
lifecycle step becomes a :class:`pbv.core.StepResult`; the first fatal step
sets ``VmResult.failure_code`` and skips the remaining steps, but cleanup
always runs. Unexpected exceptions are contained per VM (``INTERNAL_ERROR``).
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pbv.config import Config
from pbv.core import (
    ApiError,
    BackupRef,
    CheckContext,
    CheckResult,
    CheckSuite,
    CleanupError,
    ConsoleCapturer,
    GuestAgent,
    GuestAgentError,
    InterruptedRun,
    NodeShell,
    Notifier,
    OsFamily,
    PbvError,
    PbvTimeoutError,
    PreflightError,
    PveApi,
    RunReport,
    SafetyError,
    Status,
    StepResult,
    TaskResult,
    VmResult,
    VmTarget,
    utc_now_iso,
)
from pbv.orchestrator.preflight import parse_tags, preflight
from pbv.orchestrator.sanitize import sanitize_config, split_privileged
from pbv.orchestrator.signals import StopFlag

log = logging.getLogger("pbv.orchestrator")
# Tracebacks go only to the run/VM log files, never to the console.
_trace = logging.getLogger("pbv.orchestrator.trace")
_trace.propagate = False
_trace.setLevel(logging.DEBUG)

KEEP_TAG = "pbv-keep"
START_TIMEOUT_S = 120
STOP_TIMEOUT_S = 120
DESTROY_TIMEOUT_S = 300
BOOT_POLL_S = 5
CLEANUP_BACKOFF_S = (5, 15, 30)
TASK_WAIT_CHUNK_S = 10.0
SANITIZE_403_HINT = "token lacks privilege — hostpci/usb/args/hookscript changes need root@pam; configure [node_shell]"
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def new_run_id(now: datetime | None = None) -> str:
    """``YYYYMMDDTHHMMSSZ-xxxx`` (UTC timestamp plus 4 random hex digits)."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    return f"{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(2)}"


def exit_code(report: RunReport, *, fail_on_warn: bool = False) -> int:
    """Process exit code for a finished run (SPEC §8; 2 for config and 4 for lock are the CLI's).

    Precedence 3 > 130 > 2 > 1 > 0: a leftover VM always surfaces as 3, even on interrupt.
    """
    if report.sweep_failures or any(not vm.cleanup_ok for vm in report.vms):
        return 3
    if report.interrupted:
        return 130
    if any(step.status in (Status.FAIL, Status.ERROR) for step in report.preflight):
        return 2
    bad = {Status.FAIL, Status.ERROR} | ({Status.WARN} if fail_on_warn else set())
    if report.status in bad or any(vm.status in bad for vm in report.vms):
        return 1
    return 0


class _Fatal(PbvError):
    """Internal: a lifecycle step failed fatally (already recorded)."""

    def __init__(self, code: str, status: Status, message: str) -> None:
        super().__init__(message, code=code)
        self.status = status


@dataclass
class _Outcome:
    """What a successful (or non-fatally failed) step function returns."""

    message: str = ""
    status: Status = Status.PASS
    code: str = ""


@dataclass
class _VmRun:
    """Mutable state of one VM's lifecycle."""

    target: VmTarget
    result: VmResult
    work_dir: Path
    t0: float
    backup: BackupRef | None = None
    guest: GuestAgent | None = None
    os: OsFamily = OsFamily.UNKNOWN
    started: bool = False
    interrupted: bool = False
    fatal: tuple[str, str] | None = None
    nonfatal: tuple[str, str] | None = None
    notes: list[str] = field(default_factory=list)


class _ObservedApi:
    """Transparent PveApi proxy that counts connection-level ``ApiError`` (status None)."""

    def __init__(self, api: PveApi) -> None:
        self._api = api
        self.unreachable = 0

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._api, name)
        if not callable(attr):
            return attr

        def call(*args: Any, **kwargs: Any) -> Any:
            try:
                return attr(*args, **kwargs)
            except ApiError as exc:
                if exc.status is None:
                    self.unreachable += 1
                raise

        return call


class Runner:
    """Runs the validation cycle against one restore node (see module docstring)."""

    def __init__(
        self,
        cfg: Config,
        api: PveApi,
        checks: CheckSuite,
        notifiers: Sequence[Notifier],
        *,
        guest_factory: Callable[[int], GuestAgent],
        console: ConsoleCapturer | None = None,
        node_shell: NodeShell | None = None,
        run_id: str | None = None,
        should_stop: Callable[[], bool] = lambda: False,
        stop_flag: StopFlag | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        log_dir: Path | None = None,
        tool_version: str = "",
    ) -> None:
        self.cfg = cfg
        self._api = _ObservedApi(api)
        self.api: Any = self._api
        self.checks = checks
        self.notifiers = list(notifiers)
        self.guest_factory = guest_factory
        self.console = console
        self.node_shell = node_shell
        self.run_id = run_id or new_run_id()
        self.stop_flag = stop_flag
        self._should_stop_cb = should_stop
        self.sleep = sleep
        self.clock = clock
        self.log_dir = Path(log_dir) if log_dir is not None else cfg.run.log_dir
        self.tool_version = tool_version
        self.created_by_run: set[int] = set()
        self.last_sweep_failures: list[str] = []
        self._check_warnings_logged = 0

    # ── small helpers ──────────────────────────────────────────────────────────
    def _should_stop(self) -> bool:
        flag = self.stop_flag
        return bool(self._should_stop_cb() or (flag is not None and (flag() or flag.count > 0)))

    def _check_stop(self, where: str) -> None:
        if self._should_stop():
            raise InterruptedRun(f"interrupted {where}")

    @contextmanager
    def _cleanup_phase(self) -> Iterator[None]:
        """Signals are only recorded while cleanup runs (SPEC §4)."""
        if self.stop_flag is None:
            yield
            return
        previous = self.stop_flag.in_cleanup
        self.stop_flag.in_cleanup = True
        try:
            yield
        finally:
            self.stop_flag.in_cleanup = previous

    @contextmanager
    def _file_log(self, path: Path) -> Iterator[Path | None]:
        """Attach a DEBUG file handler to the ``pbv`` logger tree for the block's duration."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(path, encoding="utf-8")
        except OSError as exc:
            log.warning("LOG_FILE_UNAVAILABLE path=%s error=%s", path, exc.strerror)
            yield None
            return
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        loggers = (logging.getLogger("pbv"), _trace)
        for lg in loggers:
            lg.addHandler(handler)
        try:
            yield path
        finally:
            for lg in loggers:
                lg.removeHandler(handler)
            handler.close()

    def _wait(self, upid: str, timeout_s: float) -> TaskResult:
        """``wait_task`` in short chunks so ``should_stop`` is honoured (raises PbvTimeoutError)."""
        start = self.clock()
        waited = 0.0
        while True:
            self._check_stop("while waiting for a task")
            remaining = timeout_s - max(waited, self.clock() - start)
            if remaining <= 0:
                raise PbvTimeoutError(f"task {upid} did not finish within {timeout_s:g}s")
            chunk = min(TASK_WAIT_CHUNK_S, remaining)
            try:
                return self.api.wait_task(upid, chunk)
            except PbvTimeoutError:
                waited += chunk

    def _notify(self, report: RunReport, method: str, *args: Any) -> None:
        for n in self.notifiers:
            name = getattr(n, "name", type(n).__name__)
            try:
                getattr(n, method)(*args)
            except PbvError as exc:
                report.notify_errors.append(f"{name}: {exc.code} {exc}")
                log.error("NOTIFY_FAIL notifier=%s event=%s code=%s error=%s", name, method, exc.code, exc)
            except Exception as exc:  # boundary: a notifier bug must not change the run outcome
                report.notify_errors.append(f"{name}: NOTIFY_FAIL {type(exc).__name__}: {exc}")
                log.error("NOTIFY_FAIL notifier=%s event=%s error=%s", name, method, type(exc).__name__)
                _trace.debug("notifier %s.%s traceback", name, method, exc_info=True)

    # ── targets ────────────────────────────────────────────────────────────────
    def resolve_targets(self, vmids: Sequence[int] | None = None) -> list[VmTarget]:
        """VMs to validate: ``vmids`` if given, else per ``run.selection`` (SPEC §8)."""
        if vmids:
            return [self.cfg.vm_target(v) for v in dict.fromkeys(vmids)]
        if self.cfg.run.selection == "listed":
            return list(self.cfg.vms)
        base = self.cfg.restore.temp_vmid_base
        found = {b.vmid for b in self.api.list_backups(self.cfg.restore.backup_storage)}
        out: list[VmTarget] = []
        for vmid in sorted(found - set(self.cfg.run.exclude)):
            if not 100 <= vmid < base:
                log.warning("TARGET_SKIPPED vmid=%d reason=outside source VMID range", vmid)
                continue
            out.append(self.cfg.vm_target(vmid))
        return out

    def plan(self, vmids: Sequence[int] | None = None) -> list[tuple[VmTarget, BackupRef | None]]:
        """Targets with their newest backup, for ``--dry-run``. Read-only; no preflight."""
        targets = self.resolve_targets(vmids)
        backups = self.api.list_backups(self.cfg.restore.backup_storage)
        return [(t, _newest(backups, t.vmid)) for t in targets]

    # ── destroy guard and cleanup ──────────────────────────────────────────────
    def may_destroy(self, vmid: int) -> bool:
        """True if ``vmid`` is in the temp range and tagged or created by this run."""
        if not self.cfg.is_temp_vmid(vmid):
            return False
        if vmid in self.created_by_run:
            return True
        tags = parse_tags(self.api.get_vm_config(vmid).get("tags", ""))
        return self.cfg.restore.tag in tags

    def _guard(self, vmid: int) -> None:
        if not self.may_destroy(vmid):
            log.critical("SAFETY_REFUSED vmid=%d reason=not a pbv temp VM", vmid)
            raise SafetyError(f"refusing to stop/destroy VM {vmid}: not a pbv temporary VM")

    def _unlock(self, vmid: int) -> None:
        """Clear a config ``lock`` (SPEC §4 step 1). skiplock is root@pam-only, so never sent via the API."""
        lock = self.api.get_vm_config(vmid).get("lock", "")
        if not lock:
            return
        if self.node_shell is None:
            raise PbvError(
                f"VM {vmid} is locked ({lock}); configure [node_shell] or run `qm unlock {vmid}`", code="VM_LOCKED"
            )
        self._guard(vmid)
        log.info("CLEANUP_UNLOCK vmid=%d lock=%s", vmid, lock)
        self.node_shell.unlock(vmid)

    def _destroy_once(self, vmid: int) -> bool:
        if not self.api.vm_exists(vmid):
            return False
        self._guard(vmid)
        self._unlock(vmid)
        if self.api.vm_status(vmid) != "stopped":
            self._guard(vmid)
            res = self.api.wait_task(self.api.stop_vm(vmid), STOP_TIMEOUT_S)
            if not res.ok:
                raise CleanupError(f"stop task failed: {res.exitstatus}")
        self._guard(vmid)
        res = self.api.wait_task(self.api.destroy_vm(vmid), DESTROY_TIMEOUT_S)
        if not res.ok:
            raise CleanupError(f"destroy task failed: {res.exitstatus}")
        if self.api.vm_exists(vmid):
            raise CleanupError(f"VM {vmid} still exists after destroy")
        return True

    def _destroy(self, vmid: int) -> bool:
        """Unlock + stop + destroy + verify with retries (SPEC §4). Raises SafetyError or CleanupError.

        Returns False if the VM did not exist (nothing to do).
        """
        last = ""
        for attempt, delay in enumerate((0, *CLEANUP_BACKOFF_S), start=1):
            if delay:
                self.sleep(delay)
            try:
                existed = self._destroy_once(vmid)
            except SafetyError:
                raise
            except PbvError as exc:
                last = str(exc) if exc.code in (CleanupError.code, ApiError.code) else f"{exc.code}: {exc}"
                log.warning("CLEANUP_RETRY vmid=%d attempt=%d error=%s", vmid, attempt, last)
                continue
            log.info("CLEANUP_OK vmid=%d attempts=%d existed=%s", vmid, attempt, existed)
            self.created_by_run.discard(vmid)
            return existed
        raise CleanupError(f"VM {vmid} could not be destroyed after {1 + len(CLEANUP_BACKOFF_S)} attempts: {last}")

    def sweep(self, include_kept: bool = False) -> list[int]:
        """Destroy tagged leftover temp VMs (never untagged ones; ``pbv-keep`` only if asked).

        Returns the destroyed VMIDs. VMs that could not be destroyed are listed
        in :attr:`last_sweep_failures` as ``"<temp vmid>: <code> <message>"``.
        """
        swept: list[int] = []
        self.last_sweep_failures = []
        with self._cleanup_phase():
            for vm in sorted(self.api.list_vms(), key=lambda v: int(v["vmid"])):
                vmid = int(vm["vmid"])
                tags = parse_tags(str(vm.get("tags", "")))
                if not self.cfg.is_temp_vmid(vmid) or self.cfg.restore.tag not in tags:
                    continue
                if KEEP_TAG in tags and not include_kept:
                    log.info("SWEEP_SKIP_KEPT vmid=%d", vmid)
                    continue
                try:
                    self._destroy(vmid)
                except PbvError as exc:
                    log.error("SWEEP_FAIL vmid=%d code=%s error=%s", vmid, exc.code, exc)
                    self.last_sweep_failures.append(f"{vmid}: {exc.code} {exc}")
                    continue
                log.info("SWEEP_OK vmid=%d", vmid)
                swept.append(vmid)
        return swept

    # ── run ────────────────────────────────────────────────────────────────────
    def run(self, vmids: Sequence[int] | None = None) -> RunReport:
        """Full cycle: preflight, sweep, every VM, notifications. Never raises PbvError."""
        t0 = self.clock()
        report = RunReport(
            run_id=self.run_id,
            target_node=self.cfg.target.node,
            started_at=utc_now_iso(),
            finished_at="",
            duration_s=0.0,
            status=Status.PASS,
            tool_version=self.tool_version,
        )
        with self._file_log(self.log_dir / self.run_id / "run.log"):
            log.info("RUN_START run_id=%s node=%s version=%s", self.run_id, self.cfg.target.node, self.tool_version)
            prepared = self._prepare(report)
            self._note_interrupt(report)
            if prepared:
                try:
                    targets = self.resolve_targets(vmids)
                except PbvError as exc:
                    report.preflight.append(_step("targets", Status.ERROR, utc_now_iso(), 0.0, str(exc), exc.code))
                    log.error("TARGETS_FAIL code=%s error=%s", exc.code, exc)
                else:
                    self._run_vms(report, targets)
                    self._note_interrupt(report)
            report.status = _run_status(report)
            report.finished_at = utc_now_iso()
            report.duration_s = round(self.clock() - t0, 3)
            log.info(
                "RUN_END run_id=%s status=%s vms=%d interrupted=%s dur=%.0fs",
                self.run_id,
                report.status.value,
                len(report.vms),
                report.interrupted,
                report.duration_s,
            )
            self._notify(report, "run_finished", report)
        return report

    def _note_interrupt(self, report: RunReport) -> None:
        """A signal seen after the last poll (last check, final cleanup, sweep) still marks the run."""
        if not report.interrupted and self._should_stop():
            report.interrupted = True
            log.warning("RUN_INTERRUPTED stop requested; the report is marked interrupted")

    def _prepare(self, report: RunReport) -> bool:
        """Preflight and leftover sweep; False if preflight failed."""
        try:
            report.preflight = preflight(self.api, self.cfg, self.node_shell)
        except PreflightError as exc:
            report.preflight = list(exc.steps)
            return False
        except Exception as exc:  # boundary: malformed API data must still yield a report
            msg = f"{type(exc).__name__}: {exc}"
            report.preflight.append(_step("preflight", Status.ERROR, utc_now_iso(), 0.0, msg, "INTERNAL_ERROR"))
            log.error("PREFLIGHT_FAIL error=%s", msg)
            _trace.debug("preflight traceback", exc_info=True)
            return False
        if self.cfg.run.sweep_leftovers:
            try:
                report.leftovers_swept = self.sweep()
                report.sweep_failures = list(self.last_sweep_failures)
            except PbvError as exc:
                log.error("SWEEP_FAIL code=%s error=%s", exc.code, exc)
            except Exception as exc:  # boundary: a failed sweep must not prevent the run
                log.error("SWEEP_FAIL error=%s: %s", type(exc).__name__, exc)
                _trace.debug("sweep traceback", exc_info=True)
        return True

    def _run_vms(self, report: RunReport, targets: Sequence[VmTarget]) -> None:
        if not targets:
            log.warning("NO_TARGETS no VMs selected")
        streak = 0
        for target in targets:
            if not report.interrupted and self._should_stop():
                report.interrupted = True
                log.warning("RUN_INTERRUPTED remaining VMs are not run")
            if report.interrupted:
                report.vms.append(_not_run(target, Status.SKIPPED, "NOT_RUN", "run interrupted"))
                continue
            if streak >= 2:
                report.vms.append(
                    _not_run(target, Status.ERROR, "API_UNREACHABLE", "API unreachable for two VMs in a row")
                )
                continue
            before = self._api.unreachable
            st = self._process_vm(target)
            report.vms.append(st.result)
            report.interrupted = report.interrupted or st.interrupted
            streak = streak + 1 if self._api.unreachable > before else 0
            if streak >= 2:
                log.error("API_UNREACHABLE two consecutive VMs hit connection errors; aborting remaining VMs")
            report.status = _run_status(report)
            self._notify(report, "vm_finished", st.result, report)

    # ── per-VM lifecycle ───────────────────────────────────────────────────────
    def _process_vm(self, target: VmTarget) -> _VmRun:
        work_dir = self.log_dir / self.run_id / str(target.vmid)
        st = _VmRun(
            target=target,
            result=VmResult(
                vmid=target.vmid,
                temp_vmid=target.temp_vmid,
                name=target.name_hint,
                status=Status.PASS,
                started_at=utc_now_iso(),
                duration_s=0.0,
            ),
            work_dir=work_dir,
            t0=self.clock(),
        )
        with self._file_log(work_dir / "vm.log") as log_file:
            st.result.log_file = str(log_file) if log_file else ""
            log.info("VM_START vmid=%d temp=%d run_id=%s", target.vmid, target.temp_vmid, self.run_id)
            # Cleanup runs in ``finally`` so that even SystemExit (re-raised afterwards) leaves no VM behind.
            try:
                self._contained_lifecycle(st)
                if st.started and not st.interrupted:
                    self._safe_screenshot(st)
            except KeyboardInterrupt:
                st.interrupted = True
                self._mark(st, InterruptedRun.code, Status.ERROR, "interrupted (KeyboardInterrupt)", fatal=True)
                log.warning("VM_INTERRUPTED vmid=%d reason=KeyboardInterrupt", target.vmid)
            finally:
                self._cleanup_vm(st)
                self._finish_vm(st)
        return st

    def _contained_lifecycle(self, st: _VmRun) -> None:
        """Run the lifecycle; every Exception is recorded on the VM (SPEC §2)."""
        try:
            self._lifecycle(st)
        except _Fatal:
            pass  # recorded by _step
        except InterruptedRun as exc:
            st.interrupted = True
            self._mark(st, exc.code, Status.ERROR, str(exc), fatal=True)
            log.warning("VM_INTERRUPTED vmid=%d", st.target.vmid)
        except Exception as exc:  # boundary: one VM's bug must not stop the run
            msg = f"{type(exc).__name__}: {exc}"
            self._mark(st, "INTERNAL_ERROR", Status.ERROR, msg, fatal=True)
            log.error("INTERNAL_ERROR vmid=%d error=%s", st.target.vmid, msg)
            _trace.debug("INTERNAL_ERROR traceback vmid=%d", st.target.vmid, exc_info=True)

    def _finish_vm(self, st: _VmRun) -> None:
        res = st.result
        code, message = st.fatal or st.nonfatal or ("", "")
        res.failure_code, res.failure_message = code, message
        res.sanitized.extend(st.notes)
        res.duration_s = round(self.clock() - st.t0, 3)
        log.info(
            "VM_END vmid=%d temp=%d status=%s code=%s cleanup_ok=%s dur=%.0fs",
            st.target.vmid,
            st.target.temp_vmid,
            res.status.value,
            res.failure_code or "-",
            res.cleanup_ok,
            res.duration_s,
        )

    def _mark(self, st: _VmRun, code: str, status: Status, message: str, *, fatal: bool) -> None:
        st.result.status = Status.worst([st.result.status, status])
        if fatal and st.fatal is None:
            st.fatal = (code, message)
        elif not fatal and st.nonfatal is None:
            st.nonfatal = (code, message)

    def _step(
        self,
        st: _VmRun,
        name: str,
        fn: Callable[[], _Outcome | str],
        *,
        api_fail: tuple[str, Status] = ("API_ERROR", Status.ERROR),
    ) -> None:
        """Run one lifecycle step and record its StepResult (raises _Fatal on fatal failure)."""
        self._check_stop(f"before step {name}")
        started, t0 = utc_now_iso(), self.clock()

        def record(status: Status, message: str, code: str = "") -> None:
            dur = round(self.clock() - t0, 3)
            st.result.steps.append(_step(name, status, started, dur, message, code))
            level = logging.INFO if status in (Status.PASS, Status.SKIPPED) else logging.WARNING
            log.log(
                level,
                "STEP vmid=%d step=%s status=%s code=%s %s",
                st.target.vmid,
                name,
                status.value,
                code or "-",
                message,
            )

        try:
            out = fn()
        except _Fatal as exc:
            record(exc.status, str(exc), exc.code)
            self._mark(st, exc.code, exc.status, str(exc), fatal=True)
            raise
        except InterruptedRun as exc:
            record(Status.ERROR, str(exc), exc.code)
            raise
        except ApiError as exc:
            code, status = api_fail
            if exc.status is None:
                status = Status.ERROR
            msg = f"{name}: {exc}"
            record(status, msg, code)
            self._mark(st, code, status, msg, fatal=True)
            raise _Fatal(code, status, msg) from exc
        except Exception as exc:
            record(Status.ERROR, f"{type(exc).__name__}: {exc}", "INTERNAL_ERROR")
            raise
        if isinstance(out, str):
            out = _Outcome(out)
        record(out.status, out.message, out.code)
        if out.code and out.status.rank > Status.PASS.rank:
            self._mark(st, out.code, out.status, out.message, fatal=False)
        elif out.status is Status.WARN:
            st.result.status = Status.worst([st.result.status, Status.WARN])

    def _lifecycle(self, st: _VmRun) -> None:
        self._step(st, "resolve_backup", lambda: self._resolve_backup(st))
        if self.cfg.restore.max_backup_age_h > 0:
            self._step(st, "backup_age", lambda: self._backup_age(st))
        self._step(st, "temp_vmid", lambda: self._temp_vmid(st), api_fail=("TEMP_VMID_BUSY", Status.ERROR))
        self._step(st, "space", lambda: self._space(st))
        self._step(st, "restore", lambda: self._restore(st), api_fail=("RESTORE_FAIL", Status.FAIL))
        self._step(st, "mark", lambda: self._mark_vm(st), api_fail=("SANITIZE_FAIL", Status.ERROR))
        self._step(st, "sanitize", lambda: self._sanitize(st), api_fail=("SANITIZE_FAIL", Status.ERROR))
        self._step(st, "start", lambda: self._start(st), api_fail=("START_FAIL", Status.FAIL))
        self._step(st, "boot", lambda: self._boot(st), api_fail=("BOOT_FAIL", Status.FAIL))
        self._step(st, "settle", lambda: self._settle(st))
        self._step(st, "checks", lambda: self._checks(st), api_fail=("CHECKS_FAILED", Status.ERROR))

    # ── steps ──────────────────────────────────────────────────────────────────
    def _resolve_backup(self, st: _VmRun) -> str:
        backup = _newest(self.api.list_backups(self.cfg.restore.backup_storage), st.target.vmid)
        if backup is None:
            raise _Fatal(
                "NO_BACKUP", Status.FAIL, f"no backup of VM {st.target.vmid} on {self.cfg.restore.backup_storage}"
            )
        st.backup = st.result.backup = backup
        if not st.result.name:
            st.result.name = backup.notes.splitlines()[0].strip() if backup.notes.strip() else ""
        log.info(
            "BACKUP_SELECTED vmid=%d volid=%s ctime=%d size=%d", st.target.vmid, backup.volid, backup.ctime, backup.size
        )
        return f"newest backup {backup.volid}"

    def _backup_age(self, st: _VmRun) -> _Outcome:
        assert st.backup is not None
        age_h = (time.time() - st.backup.ctime) / 3600
        limit = self.cfg.restore.max_backup_age_h
        if age_h > limit:
            return _Outcome(f"backup is {age_h:.1f}h old (limit {limit}h)", Status.FAIL, "BACKUP_TOO_OLD")
        return f"backup is {age_h:.1f}h old (limit {limit}h)"

    def _temp_vmid(self, st: _VmRun) -> _Outcome | str:
        temp = st.target.temp_vmid
        if not self.api.vm_exists(temp):
            return f"temp VMID {temp} is free"
        busy = f"temp VMID {temp} is in use"
        if not self.may_destroy(temp):
            raise _Fatal("TEMP_VMID_BUSY", Status.ERROR, f"{busy} by a VM pbv does not own")
        if KEEP_TAG in parse_tags(self.api.get_vm_config(temp).get("tags", "")):
            raise _Fatal("TEMP_VMID_BUSY", Status.ERROR, f"{busy} by a kept VM; run `pbv cleanup --include-kept`")
        try:
            with self._cleanup_phase():
                self._destroy(temp)
        except PbvError as exc:
            raise _Fatal("TEMP_VMID_BUSY", Status.ERROR, f"{busy}; removing the leftover failed: {exc}") from exc
        return f"removed leftover temp VM {temp}"

    def _space(self, st: _VmRun) -> _Outcome:
        assert st.backup is not None
        name = self.cfg.restore.target_storage
        info = next((s for s in self.api.storage_list() if s.get("storage") == name), {})
        avail = info.get("avail")
        if st.backup.size <= 0 or avail is None:
            return _Outcome("skipped (backup size or free space unknown)", Status.SKIPPED)
        need = st.backup.size * self.cfg.restore.min_free_space_ratio
        if int(avail) < need:
            raise _Fatal(
                "INSUFFICIENT_SPACE",
                Status.ERROR,
                f"{name} has {int(avail)} bytes free, need {need:.0f} ({self.cfg.restore.min_free_space_ratio}× backup)",
            )
        return _Outcome(f"{name} has {int(avail)} bytes free, need {need:.0f}")

    def _restore(self, st: _VmRun) -> str:
        assert st.backup is not None
        temp, r = st.target.temp_vmid, self.cfg.restore
        t0 = self.clock()
        log.info("RESTORE_START vmid=%d temp=%d volid=%s", st.target.vmid, temp, st.backup.volid)
        try:
            upid = self.api.restore_vm(
                temp,
                st.backup.volid,
                r.target_storage,
                unique=True,
                pool=r.pool or None,
                bwlimit_kib=r.bwlimit_kib or None,
            )
        except ApiError as exc:
            if _restore_may_have_created(exc):
                # The request may have been processed: cleanup checks vm_exists and removes it if present.
                self.created_by_run.add(temp)
            raise _Fatal(
                "RESTORE_FAIL", Status.ERROR if exc.status is None else Status.FAIL, f"restore: {exc}"
            ) from exc
        self.created_by_run.add(temp)
        try:
            res = self._wait(upid, r.restore_timeout_s)
        except (PbvTimeoutError, InterruptedRun) as exc:
            try:
                self.api.stop_task(upid)
            except ApiError as stop_exc:
                log.warning("STOP_TASK_FAIL upid=%s error=%s", upid, stop_exc)
            if isinstance(exc, InterruptedRun):
                raise
            raise _Fatal(
                "RESTORE_TIMEOUT", Status.FAIL, f"restore did not finish within {r.restore_timeout_s}s"
            ) from exc
        if not res.ok:
            tail = " | ".join(res.log_tail[-10:])
            raise _Fatal(
                "RESTORE_FAIL",
                Status.FAIL,
                f"restore task failed: {res.exitstatus}" + (f"; log: {tail}" if tail else ""),
            )
        dur = self.clock() - t0
        log.info("RESTORE_OK vmid=%d temp=%d dur=%.0fs", st.target.vmid, temp, dur)
        return f"restored to {temp} on {r.target_storage} in {dur:.0f}s"

    def _mark_vm(self, st: _VmRun) -> str:
        temp = st.target.temp_vmid
        cfg = self.api.get_vm_config(temp)
        if not st.result.name:
            st.result.name = cfg.get("name", "") or f"vm{st.target.vmid}"
        tags = ";".join(dict.fromkeys([*parse_tags(cfg.get("tags", "")), self.cfg.restore.tag]))
        marker = (
            f"pbv temporary restore test of VM {st.target.vmid} ({st.result.name}) — run {self.run_id} — safe to delete"
        )
        delete = ["protection"] if "protection" in cfg else []
        self.api.update_vm_config(temp, {"tags": tags, "description": marker, "onboot": "0"}, delete)
        return f"tagged {tags}, onboot=0" + (", protection removed" if delete else "")

    def _sanitize(self, st: _VmRun) -> str:
        temp = st.target.temp_vmid
        cfg = self.api.get_vm_config(temp)
        storages = {str(s.get("storage")) for s in self.api.storage_list()}
        plan = sanitize_config(
            cfg, bridge=self.cfg.restore.isolated_bridge, storages=storages, opts=self.cfg.sanitize, vmid=temp
        )
        for w in plan.warnings:
            log.warning("SANITIZE_WARNING vmid=%d %s", st.target.vmid, w)
        api_set, api_delete, root_set, root_delete = split = split_privileged(
            plan, cfg, have_root=self.node_shell is not None
        )
        if split.root_keys and self.node_shell is None:
            raise _Fatal(
                "SANITIZE_NEEDS_ROOT",
                Status.FAIL,
                f"needs root@pam for: {', '.join(split.root_keys)} — configure [node_shell]",
            )
        if api_set or api_delete:
            try:
                self.api.update_vm_config(temp, api_set, api_delete)
            except ApiError as exc:
                if exc.status == 403 or "only root" in str(exc):
                    raise _Fatal("SANITIZE_FAIL", Status.ERROR, f"sanitize: {exc} ({SANITIZE_403_HINT})") from exc
                raise
        if self.node_shell is not None and (root_set or root_delete):
            log.info("SANITIZE_ROOT vmid=%d temp=%d keys=%s", st.target.vmid, temp, ",".join(split.root_keys))
            try:
                self.node_shell.qm_set(temp, root_set, root_delete)
            except PbvError as exc:
                raise _Fatal(exc.code, Status.ERROR, f"sanitize (qm set): {exc}") from exc
        st.result.sanitized.extend([*plan.notes, *(f"WARNING: {w}" for w in plan.warnings)])
        log.info("SANITIZE_OK vmid=%d temp=%d changes=%d", st.target.vmid, temp, len(plan.notes) + len(plan.warnings))
        return f"{len(plan.notes)} change(s), {len(plan.warnings)} warning(s)"

    def _start(self, st: _VmRun) -> str:
        temp = st.target.temp_vmid
        upid = self.api.start_vm(temp)
        st.started = True
        try:
            res = self._wait(upid, START_TIMEOUT_S)
        except PbvTimeoutError as exc:
            raise _Fatal("START_FAIL", Status.FAIL, f"start task did not finish within {START_TIMEOUT_S}s") from exc
        if not res.ok:
            raise _Fatal("START_FAIL", Status.FAIL, f"start failed: {res.exitstatus}")
        log.info("START_OK vmid=%d temp=%d", st.target.vmid, temp)
        return f"started {temp}"

    def _ping(self, temp: int) -> bool:
        try:
            return bool(self.api.agent_ping(temp))
        except ApiError as exc:
            if exc.status is None:
                raise
            log.debug("agent_ping vmid=%d error=%s", temp, exc)
            return False

    def _boot(self, st: _VmRun) -> str:
        temp, timeout = st.target.temp_vmid, st.target.boot_timeout_s
        start = self.clock()
        while True:
            self._check_stop("during boot wait")
            if self.api.vm_status(temp) == "stopped":
                raise _Fatal("BOOT_FAIL", Status.FAIL, f"VM {temp} stopped while booting")
            elapsed = self.clock() - start
            if self._ping(temp):
                log.info("BOOT_OK vmid=%d temp=%d dur=%.0fs", st.target.vmid, temp, elapsed)
                return f"guest agent answered after {elapsed:.0f}s"
            if elapsed >= timeout:
                raise _Fatal("BOOT_TIMEOUT", Status.FAIL, f"guest agent did not answer within {timeout}s")
            self.sleep(BOOT_POLL_S)

    def _settle(self, st: _VmRun) -> str:
        if self.cfg.run.settle_s:
            self.sleep(self.cfg.run.settle_s)
        self._check_stop("after settle")
        st.guest = self.guest_factory(st.target.temp_vmid)
        if st.target.os is not None:
            st.os = st.target.os
        else:
            try:
                st.os = st.guest.os_family()
            except (GuestAgentError, ApiError) as exc:
                log.warning("OS_DETECT_FAIL vmid=%d error=%s", st.target.vmid, exc)
                st.os = OsFamily.UNKNOWN
        try:
            ips = st.guest.ip_addresses()
        except (GuestAgentError, ApiError) as exc:
            log.warning("IP_DETECT_FAIL vmid=%d error=%s", st.target.vmid, exc)
            ips = []
        st.result.os = st.os.value
        st.result.guest_ips = list(ips)
        return f"os={st.os.value} ips={','.join(ips) or '-'}"

    def _checks(self, st: _VmRun) -> _Outcome:
        assert st.guest is not None
        specs = self.checks.plan(st.target, st.guest, st.os)
        warnings = list(getattr(self.checks, "warnings", None) or [])
        for w in warnings[self._check_warnings_logged :]:
            log.warning("CHECK_PLAN_WARNING vmid=%d %s", st.target.vmid, w)
        self._check_warnings_logged = len(warnings)
        ctx = CheckContext(
            run_id=self.run_id,
            target_node=self.cfg.target.node,
            vmid=st.target.vmid,
            temp_vmid=st.target.temp_vmid,
            vm_name=st.result.name,
            os=st.os,
            guest_ips=tuple(st.result.guest_ips),
            work_dir=st.work_dir,
            config_dir=self.cfg.config_dir,
        )
        for spec in specs:
            res = self.checks.run(spec, st.guest, ctx)
            st.result.checks.append(res)
            log.info("CHECK vmid=%d name=%s status=%s %s", st.target.vmid, res.name, res.status.value, res.summary)
            self._check_stop(f"after check {spec.name}")
        out = _checks_outcome(st.result.checks)
        if out.code:
            raise _Fatal(out.code, out.status, out.message)
        return out

    def _safe_screenshot(self, st: _VmRun) -> None:
        """The screenshot step is never fatal, not even through a bug in it (SPEC §2 step 11)."""
        try:
            self._screenshot(st)
        except Exception as exc:  # boundary: a screenshot bug must not skip cleanup or the report
            log.warning("SCREENSHOT_FAIL vmid=%d error=%s", st.target.vmid, type(exc).__name__)
            _trace.debug("screenshot traceback vmid=%d", st.target.vmid, exc_info=True)
            st.result.steps.append(_step("screenshot", Status.WARN, utc_now_iso(), 0.0, f"screenshot failed: {exc}"))

    def _screenshot(self, st: _VmRun) -> None:
        shot = self.cfg.screenshot
        if self.console is None or not shot.enabled:
            return
        if not (shot.when == "always" or st.result.status.rank > Status.PASS.rank):
            return
        started, t0 = utc_now_iso(), self.clock()
        temp = st.target.temp_vmid
        try:
            path = self.console.capture(temp, st.work_dir / f"console-{temp}")
        except Exception as exc:  # boundary: ConsoleCapturer must never raise; never fatal
            log.warning("SCREENSHOT_FAIL vmid=%d error=%s", st.target.vmid, type(exc).__name__)
            _trace.debug("screenshot traceback", exc_info=True)
            path = None
        dur = round(self.clock() - t0, 3)
        if path is None:
            st.result.steps.append(_step("screenshot", Status.WARN, started, dur, "console capture failed"))
            return
        st.result.screenshots.append(str(path))
        st.result.steps.append(_step("screenshot", Status.PASS, started, dur, str(path)))
        log.info("SCREENSHOT_OK vmid=%d path=%s", st.target.vmid, path)

    def _keep(self, st: _VmRun) -> bool:
        """keep_on_failure: tag the failed VM ``pbv-keep`` and leave it running. True if kept."""
        temp = st.target.temp_vmid
        try:
            self._guard(temp)
            tags = parse_tags(self.api.get_vm_config(temp).get("tags", ""))
            merged = ";".join(dict.fromkeys([*tags, self.cfg.restore.tag, KEEP_TAG]))
            self.api.update_vm_config(temp, {"tags": merged})
        except (ApiError, SafetyError) as exc:
            log.warning("KEEP_FAIL vmid=%d error=%s (destroying instead)", st.target.vmid, exc)
            return False
        st.notes.append("kept for debugging")
        log.warning("VM_KEPT vmid=%d temp=%d tag=%s", st.target.vmid, temp, KEEP_TAG)
        return True

    def _cleanup_vm(self, st: _VmRun) -> None:
        temp = st.target.temp_vmid
        started, t0 = utc_now_iso(), self.clock()

        def record(status: Status, message: str, code: str = "") -> None:
            st.result.steps.append(_step("cleanup", status, started, round(self.clock() - t0, 3), message, code))

        if temp not in self.created_by_run:
            record(Status.SKIPPED, "nothing to clean up (no restore attempted)")
            return
        not_kept = ""
        with self._cleanup_phase():
            try:
                failed = st.result.status.rank >= Status.FAIL.rank
                want_keep = self.cfg.restore.keep_on_failure and failed and not st.interrupted
                sanitize = [s.status for s in st.result.steps if s.name == "sanitize"]
                if want_keep and sanitize != [Status.PASS]:
                    # Unsanitized: NICs may still be on the production bridge, passthrough still attached.
                    not_kept = f"not kept: sanitize {'failed' if sanitize else 'did not run'}"
                    st.notes.append(not_kept)
                    log.warning("KEEP_REFUSED vmid=%d temp=%d reason=sanitize did not pass", st.target.vmid, temp)
                elif want_keep and self.api.vm_exists(temp) and self._keep(st):
                    record(Status.SKIPPED, f"kept for debugging (keep_on_failure): VM {temp} tagged {KEEP_TAG}")
                    self.created_by_run.discard(temp)
                    return
                existed = self._destroy(temp)
            except SafetyError as exc:
                record(Status.ERROR, str(exc), exc.code)
                self._mark(st, exc.code, Status.ERROR, str(exc), fatal=True)
                return
            except Exception as exc:  # boundary: any failure here means the VM may still exist
                msg = f"MANUAL CLEANUP REQUIRED: VM {temp} on {self.cfg.target.node} — {exc}"
                if not isinstance(exc, PbvError):
                    _trace.debug("cleanup traceback vmid=%d", temp, exc_info=True)
                st.result.cleanup_ok = False
                record(Status.ERROR, msg, CleanupError.code)
                self._mark(st, CleanupError.code, Status.ERROR, msg, fatal=True)
                log.critical(
                    "CLEANUP_FAIL vmid=%d temp=%d node=%s error=%s", st.target.vmid, temp, self.cfg.target.node, exc
                )
                return
        message = f"destroyed {temp}" if existed else f"VM {temp} does not exist; nothing to destroy"
        record(Status.PASS, message + (f" ({not_kept})" if not_kept else ""))


# ── module helpers ──────────────────────────────────────────────────────────────
def _restore_may_have_created(exc: ApiError) -> bool:
    """Whether a failed restore POST may still have created the temp VM.

    A 4xx means PVE refused the request before doing anything. "already exists"
    means the VMID belongs to someone else (temp_vmid checked it was free just
    before), so claiming it would let cleanup destroy a foreign VM.
    """
    if "already exists" in str(exc).lower():
        return False
    return exc.status is None or not 400 <= exc.status < 500


def _step(name: str, status: Status, started: str, dur: float, message: str = "", code: str = "") -> StepResult:
    return StepResult(name=name, status=status, started_at=started, duration_s=dur, message=message, error_code=code)


def _newest(backups: Sequence[BackupRef], vmid: int) -> BackupRef | None:
    mine = [b for b in backups if b.vmid == vmid]
    return max(mine, key=lambda b: b.ctime) if mine else None


def _not_run(target: VmTarget, status: Status, code: str, message: str) -> VmResult:
    return VmResult(
        vmid=target.vmid,
        temp_vmid=target.temp_vmid,
        name=target.name_hint,
        status=status,
        started_at=utc_now_iso(),
        duration_s=0.0,
        failure_code=code,
        failure_message=message,
    )


def _checks_outcome(results: Sequence[CheckResult]) -> _Outcome:
    def effective(r: CheckResult) -> Status:
        if not r.critical and r.status.rank > Status.WARN.rank:
            return Status.WARN
        return r.status

    ran = [effective(r) for r in results if r.status is not Status.SKIPPED]
    counts = {s: ran.count(s) for s in (Status.PASS, Status.WARN, Status.FAIL, Status.ERROR)}
    summary = f"{len(results)} check(s): " + ", ".join(f"{n} {s.value}" for s, n in counts.items() if n)
    if not results:
        return _Outcome("no checks planned")
    worst = Status.worst(ran, default=Status.PASS)
    failed = [r.name for r in results if r.critical and r.status in (Status.FAIL, Status.ERROR)]
    if failed:
        return _Outcome(f"{summary}; failed: {', '.join(failed)}", worst, "CHECKS_FAILED")
    return _Outcome(summary, worst)


def _run_status(report: RunReport) -> Status:
    preflight_failed = any(s.status in (Status.FAIL, Status.ERROR) for s in report.preflight)
    if report.interrupted or preflight_failed or report.sweep_failures or any(not vm.cleanup_ok for vm in report.vms):
        return Status.ERROR
    return Status.worst([vm.status for vm in report.vms])
