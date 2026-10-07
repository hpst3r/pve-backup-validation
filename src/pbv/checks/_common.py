"""Shared building blocks for check implementations.

An implementation returns an :class:`Outcome` (what happened, independent of
``critical``); the engine maps it to a :class:`pbv.core.Status`. Guest
commands go through :class:`Attempt`, which bounds every exec by the
remaining per-attempt budget and turns a guest-side timeout into
:class:`pbv.core.PbvTimeoutError`.
"""

from __future__ import annotations

import enum
import re
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pbv.core import ApiError, CheckContext, CheckSpec, ExecResult, GuestAgent, GuestAgentError, PbvTimeoutError

SUMMARY_MAX = 200
DETAIL_MAX = 8192
OUTPUT_CAP = 64 * 1024
DIAG_TIMEOUT_S = 15.0

POWERSHELL = ("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Kind(enum.Enum):
    """Raw result of one attempt, before the ``critical`` flag is applied."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"  # check condition not met (FAIL if critical, else WARN); retried
    WARN = "warn"  # WARN regardless of critical (warn_exit, degraded fallback); retried
    SKIP = "skip"  # not applicable (OS mismatch); never retried
    AGENT_ERROR = "agent_error"  # guest agent / API failure; retried (guest may still be booting)
    ERROR = "error"  # config/setup/internal problem; never retried


RETRYABLE = frozenset({Kind.FAIL, Kind.WARN, Kind.AGENT_ERROR})


@dataclass(frozen=True)
class Outcome:
    kind: Kind
    summary: str
    detail: str = ""


class Attempt:
    """One bounded attempt of a check: guest access plus a deadline."""

    def __init__(
        self, spec: CheckSpec, ctx: CheckContext, guest: GuestAgent, clock: Callable[[], float], deadline: float
    ) -> None:
        self.spec = spec
        self.ctx = ctx
        self.guest = guest
        self.clock = clock
        self.deadline = deadline

    def remaining(self) -> float:
        return max(1.0, self.deadline - self.clock())

    def exec(self, argv: Sequence[str], *, timeout_s: float | None = None) -> ExecResult:
        """Run ``argv`` in the guest; raise :class:`PbvTimeoutError` on timeout."""
        budget = self.remaining() if timeout_s is None else min(timeout_s, self.remaining())
        res = self.guest.exec(list(argv), timeout_s=budget)
        if res.timed_out:
            raise PbvTimeoutError(timeout_message(self.spec.timeout_s))
        return res

    def try_exec(self, argv: Sequence[str], *, timeout_s: float = DIAG_TIMEOUT_S) -> ExecResult | None:
        """Best-effort diagnostic exec: ``None`` on any guest failure or timeout."""
        try:
            return self.exec(argv, timeout_s=timeout_s)
        except (GuestAgentError, ApiError, PbvTimeoutError):
            return None


def timeout_message(timeout_s: float) -> str:
    return f"timed out after {int(timeout_s)}s (guest process may still be running)"


# ── text helpers ───────────────────────────────────────────────────────────────


def one_line(text: str, limit: int = SUMMARY_MAX) -> str:
    """Collapse whitespace (incl. CR/LF) and cap at ``limit`` characters."""
    s = " ".join(str(text).split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def truncate_detail(text: str, limit: int = DETAIL_MAX) -> str:
    """Keep the tail of ``text`` within ``limit`` UTF-8 bytes, marking truncation."""
    data = text.encode("utf-8", errors="replace")
    if len(data) <= limit:
        return text
    marker_room = 40
    keep = limit - marker_room
    cut = len(data) - keep
    tail = data[cut:].decode("utf-8", errors="ignore")
    return f"[…truncated {cut} bytes]\n{tail}"


def cap(text: str, limit: int = OUTPUT_CAP) -> str:
    return text if len(text) <= limit else text[:limit]


def lines(text: str) -> list[str]:
    """Non-empty, stripped lines; robust to CRLF and trailing whitespace."""
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def output_detail(res: ExecResult | None, *, header: str = "") -> str:
    if res is None:
        return header
    parts = [header] if header else []
    parts.append(f"exit={res.exitcode}")
    if res.stdout.strip():
        parts.append("--- stdout ---\n" + res.stdout.rstrip())
    if res.stderr.strip():
        parts.append("--- stderr ---\n" + res.stderr.rstrip())
    return "\n".join(parts)


# ── quoting / argv builders ────────────────────────────────────────────────────


def sh_argv(script: str) -> list[str]:
    return ["/bin/sh", "-c", script]


def ps_quote(value: str) -> str:
    """PowerShell single-quoted literal: no expansion, ``'`` doubled.

    PowerShell also treats the typographic quotes U+2018/U+2019/U+201A/U+201B
    as single quotes, so those are doubled too.
    """
    out = []
    for ch in str(value):
        out.append(ch)
        if ch in "'‘’‚‛":
            out.append(ch)
    return "'" + "".join(out) + "'"


def ps_argv(script: str) -> list[str]:
    return [*POWERSHELL, "-Command", script]


def sh_join(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


# ── shared evaluation helpers ──────────────────────────────────────────────────

_ADDR_RE = re.compile(r"^(?P<host>.+):(?P<port>\d+|\*)$")


def parse_listening(output: str, port: int) -> bool:
    """True if a ``ss``/``netstat`` listing shows a TCP listener on ``port``.

    Each line's first ``host:port`` token is the local address; it must end in
    exactly ``:<port>`` (``0.0.0.0:22``, ``[::]:22``, ``*:22``, ``:::22``), so
    ``:2222`` never matches ``22``. A second address token (the peer) must be a
    wildcard (``*`` or ``0``) — true for listeners in ``ss -ltn``, ``netstat
    -ltn`` and Windows ``netstat -an`` regardless of the locale of the header
    and state columns. UDP lines are ignored.
    """
    for ln in lines(output):
        toks = ln.split()
        if toks[0].lower().startswith("udp"):
            continue
        addrs = [m for t in toks if (m := _ADDR_RE.match(t))]
        if not addrs:
            continue
        local = addrs[0]
        if local.group("port") != str(port):
            continue
        if len(addrs) > 1 and addrs[1].group("port") not in ("*", "0"):
            continue
        return True
    return False


def http_accepted(code: int, expect: Sequence[int] | None) -> bool:
    if expect:
        return code in expect
    return 200 <= code < 400 or code in (401, 403)


def parse_http_output(stdout: str) -> tuple[int | None, str, str]:
    """Parse ``PBV_HTTP <code>`` [+ ``PBV_HTTP_ERR msg``] [+ ``PBV_BODY`` + body].

    Returns ``(code or None, error message, body)``.
    """
    head, sep, body = stdout.partition("PBV_BODY")
    if sep:
        body = body[2:] if body.startswith("\r\n") else body[1:] if body.startswith("\n") else body
    code: int | None = None
    err = ""
    for ln in lines(head):
        if ln.startswith("PBV_HTTP_ERR"):
            err = ln[len("PBV_HTTP_ERR") :].strip()
        elif ln.startswith("PBV_HTTP"):
            val = ln[len("PBV_HTTP") :].strip()
            if val.isdigit():
                code = int(val)
    return code, err, cap(body)


def http_url(params: Mapping[str, Any]) -> str:
    host = str(params.get("host") or "127.0.0.1")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6 literal
    return f"{params.get('scheme') or 'http'}://{host}:{int(params['port'])}{params.get('path') or '/'}"


def evaluate_http(params: Mapping[str, Any], url: str, stdout: str, detail: str) -> Outcome:
    code, err, body = parse_http_output(stdout)
    if not code:
        return Outcome(Kind.FAIL, f"{url}: no response" + (f" ({err})" if err else ""), detail)
    if not http_accepted(code, params.get("expect_status")):
        return Outcome(Kind.FAIL, f"{url}: HTTP {code} not accepted", detail)
    regex = params.get("body_regex") or ""
    if regex and not re.search(regex, body):
        return Outcome(Kind.FAIL, f"{url}: HTTP {code} but body did not match /{regex}/", detail)
    return Outcome(Kind.PASS, f"{url}: HTTP {code}")


def judge_exit(params: Mapping[str, Any], exitcode: int | None, stdout: str, *, what: str) -> Outcome:
    """Exit-code mapping for command/script/host_script. Detail is added by the caller."""
    expect = list(params.get("expect_exit") or [0])
    warn = list(params.get("warn_exit") or [])
    regex = params.get("stdout_regex") or ""
    if exitcode is None:
        return Outcome(Kind.FAIL, f"{what} ended without an exit code (killed?)")
    if exitcode in expect:
        if regex and not re.search(regex, stdout):
            return Outcome(Kind.FAIL, f"{what} exited {exitcode} but stdout did not match /{regex}/")
        return Outcome(Kind.PASS, f"{what} exited {exitcode}")
    if exitcode in warn:
        return Outcome(Kind.WARN, f"{what} exited {exitcode} (warn_exit)")
    return Outcome(Kind.FAIL, f"{what} exited {exitcode} (expected {', '.join(map(str, expect))})")


def pbv_env(spec: CheckSpec, ctx: CheckContext) -> dict[str, str]:
    """``PBV_*`` variables every guest/host script receives (SPEC §5)."""
    return {
        "PBV_RUN_ID": ctx.run_id,
        "PBV_VMID": str(ctx.vmid),
        "PBV_TEMP_VMID": str(ctx.temp_vmid),
        "PBV_VM_NAME": ctx.vm_name,
        "PBV_OS": ctx.os.value,
        "PBV_GUEST_IPS": ",".join(ctx.guest_ips),
        "PBV_GUEST_IP": ctx.guest_ips[0] if ctx.guest_ips else "",
        "PBV_TARGET_NODE": ctx.target_node,
        "PBV_CHECK_NAME": spec.name,
    }


def bad_env_names(env: Mapping[str, str]) -> list[str]:
    return sorted(k for k in env if not ENV_NAME_RE.fullmatch(k))
