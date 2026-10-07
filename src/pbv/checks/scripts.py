"""``command``, ``script`` (guest) and ``host_script`` (runner) checks.

Guest scripts are uploaded with :meth:`GuestAgent.write_file` and executed by
an explicit interpreter, so no chmod is needed. Host scripts run in their own
session/process group; on timeout the whole group gets SIGTERM, then SIGKILL
after a grace period.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shlex
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PureWindowsPath

from pbv.checks._common import (
    OUTPUT_CAP,
    POWERSHELL,
    Attempt,
    Kind,
    Outcome,
    bad_env_names,
    judge_exit,
    output_detail,
    pbv_env,
    ps_argv,
    ps_quote,
)
from pbv.core import ApiError, ExecResult, GuestAgentError, OsFamily, PbvTimeoutError

log = logging.getLogger("pbv.checks")

LINUX_TMP = "/tmp"  # noqa: S108 - guest path, not a local temp file
WINDOWS_TMP = "C:\\Windows\\Temp"
CLEANUP_TIMEOUT_S = 15.0
HOST_GRACE_S = 5.0
HOST_ENV_INHERIT = ("PATH", "LANG", "HOME")

RunHost = Callable[..., "subprocess.CompletedProcess[bytes]"]


def safe_name(name: str, limit: int = 80) -> str:
    """File-name-safe version of ``name`` (``[A-Za-z0-9._-]``)."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "check"
    return s[:limit]


# ── command ────────────────────────────────────────────────────────────────────


def check_command(att: Attempt) -> Outcome:
    argv = [str(a) for a in att.spec.params["argv"]]
    res = att.exec(argv)
    out = judge_exit(att.spec.params, res.exitcode, res.stdout, what=f"command {Path(argv[0]).name}")
    return replace(out, detail=output_detail(res))


# ── guest script ───────────────────────────────────────────────────────────────


def guest_script_path(os_family: OsFamily, run_id: str, n: int, basename: str, interpreter: str = "") -> str:
    """``/tmp/pbv-<run_id>-<n>-<basename>`` or ``C:\\Windows\\Temp\\pbv-…``.

    On Windows without an explicit interpreter, files that are not
    ``.ps1``/``.cmd``/``.bat`` get ``.ps1`` appended: ``powershell -File``
    refuses other extensions.
    """
    name = f"pbv-{safe_name(run_id, 40)}-{int(n)}-{safe_name(basename)}"
    if os_family is OsFamily.WINDOWS:
        if not interpreter and PureWindowsPath(name).suffix.lower() not in (".ps1", ".cmd", ".bat"):
            name += ".ps1"
        return f"{WINDOWS_TMP}\\{name}"
    return f"{LINUX_TMP}/{name}"


def linux_script_argv(dest: str, interpreter: str, args: Sequence[str], env: Mapping[str, str]) -> list[str]:
    """``/usr/bin/env K=V … <interpreter or /bin/sh> <dest> <args…>`` (no shell involved)."""
    interp = shlex.split(interpreter) if interpreter.strip() else ["/bin/sh"]
    return ["/usr/bin/env", *(f"{k}={v}" for k, v in env.items()), *interp, dest, *map(str, args)]


def _windows_interp_tokens(interpreter: str) -> list[str]:
    toks = shlex.split(interpreter, posix=False)
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t for t in toks]


def windows_script_argv(dest: str, interpreter: str, args: Sequence[str], env: Mapping[str, str]) -> list[str]:
    """PowerShell wrapper: ``$env:K='V'; & <interpreter> '<dest>' 'arg'…; exit $LASTEXITCODE``."""
    sets = "".join(f"$env:{k} = {ps_quote(v)}; " for k, v in env.items())
    qargs = " ".join(ps_quote(str(a)) for a in args)
    if interpreter.strip():
        toks = _windows_interp_tokens(interpreter)
        call = " ".join(ps_quote(t) for t in toks) + f" {ps_quote(dest)}"
    elif dest.lower().endswith((".cmd", ".bat")):
        call = f"cmd.exe /c {ps_quote(dest)}"
    else:
        call = " ".join(POWERSHELL) + f" -File {ps_quote(dest)}"
    return ps_argv(f"{sets}& {call}{' ' + qargs if qargs else ''}; exit $LASTEXITCODE")


def cleanup_argv(os_family: OsFamily, dest: str) -> list[str]:
    if os_family is OsFamily.WINDOWS:
        return ps_argv(f"Remove-Item -LiteralPath {ps_quote(dest)} -Force -ErrorAction SilentlyContinue")
    return ["rm", "-f", "--", dest]


def resolve_script(path: str, config_dir: Path) -> Path:
    p = Path(path).expanduser()
    return p if p.is_absolute() else config_dir / p


def check_script(att: Attempt, *, n: int, config_dir: Path) -> Outcome:
    p = att.spec.params
    os_family = att.ctx.os
    src = resolve_script(str(p["path"]), config_dir)
    env = {**pbv_env(att.spec, att.ctx), **dict(p.get("env") or {})}
    bad = bad_env_names(env)
    if bad:
        return Outcome(Kind.ERROR, f"invalid environment variable name(s): {', '.join(bad)}")
    try:
        data = src.read_bytes()
    except OSError as exc:
        return Outcome(Kind.ERROR, f"cannot read script {src}: {exc.strerror or exc}")
    interpreter = str(p.get("interpreter") or "")
    dest = guest_script_path(os_family, att.ctx.run_id, n, src.name, interpreter)
    args = [str(a) for a in p.get("args") or []]
    if os_family is OsFamily.WINDOWS:
        argv = windows_script_argv(dest, interpreter, args, env)
    else:
        argv = linux_script_argv(dest, interpreter, args, env)
    att.guest.write_file(dest, data)
    try:
        res = att.exec(argv)
    finally:
        _cleanup(att, os_family, dest)
    out = judge_exit(p, res.exitcode, res.stdout, what=f"script {src.name}")
    return replace(out, detail=output_detail(res, header=f"guest path {dest}"))


def _cleanup(att: Attempt, os_family: OsFamily, dest: str) -> None:
    try:
        att.guest.exec(cleanup_argv(os_family, dest), timeout_s=CLEANUP_TIMEOUT_S)
    except (GuestAgentError, ApiError, PbvTimeoutError) as exc:
        log.debug("SCRIPT_CLEANUP_FAIL path=%s err=%s", dest, exc)


# ── host script ────────────────────────────────────────────────────────────────


def _killpg(pgid: int, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, sig)


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def default_run_host(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    timeout_s: float,
    grace_s: float = HOST_GRACE_S,
) -> subprocess.CompletedProcess[bytes]:
    """Run ``argv`` in a new session; on timeout SIGTERM the group, SIGKILL after ``grace_s``.

    Raises :class:`subprocess.TimeoutExpired` (with any captured output) on
    timeout and :class:`OSError` if the program cannot be started.
    """
    proc = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        cwd=cwd,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        pgid = proc.pid
        _killpg(pgid, signal.SIGTERM)
        deadline = time.monotonic() + grace_s
        got: tuple[bytes, bytes] | None
        try:
            got = proc.communicate(timeout=grace_s)
        except subprocess.TimeoutExpired:
            got = None
        while _group_alive(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _group_alive(pgid):
            log.debug("HOST_SCRIPT_SIGKILL pgid=%d", pgid)
            _killpg(pgid, signal.SIGKILL)
        out, err = got if got is not None else proc.communicate()
        raise subprocess.TimeoutExpired(list(argv), timeout_s, output=out, stderr=err) from None
    return subprocess.CompletedProcess(list(argv), proc.returncode, out, err)


def host_env_for(
    att: Attempt, *, host_env: Mapping[str, str], environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Inherited PATH/LANG/HOME + ``host_env`` + ``PBV_*`` + ``PBV_WORK_DIR`` + the check's env."""
    src = os.environ if environ is None else environ
    env = {k: src[k] for k in HOST_ENV_INHERIT if k in src}
    env.update(host_env)
    env.update(pbv_env(att.spec, att.ctx))
    env["PBV_WORK_DIR"] = str(att.ctx.work_dir)
    env.update(dict(att.spec.params.get("env") or {}))
    return env


def _decode(b: bytes | str | None) -> str:
    if b is None:
        return ""
    return b if isinstance(b, str) else b.decode("utf-8", errors="replace")


def _write_output(path: Path, stdout: str, stderr: str) -> None:
    try:
        path.write_text(f"{stdout}\n--- stderr ---\n{stderr}", encoding="utf-8")
    except OSError as exc:
        log.warning("HOST_SCRIPT_OUTPUT_WRITE_FAIL path=%s err=%s", path, exc.strerror or exc)


def check_host_script(
    att: Attempt,
    *,
    config_dir: Path,
    host_env: Mapping[str, str],
    run_host: RunHost,
    environ: Mapping[str, str] | None = None,
) -> Outcome:
    p = att.spec.params
    path = resolve_script(str(p["path"]), config_dir)
    env = host_env_for(att, host_env=host_env, environ=environ)
    bad = bad_env_names(env)
    if bad:
        return Outcome(Kind.ERROR, f"invalid environment variable name(s): {', '.join(bad)}")
    work_dir = att.ctx.work_dir
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return Outcome(Kind.ERROR, f"cannot create work dir {work_dir}: {exc.strerror or exc}")
    out_file = work_dir / f"{safe_name(att.spec.name)}.out"
    argv = [str(path), *(str(a) for a in p.get("args") or [])]
    timeout = att.remaining()
    try:
        cp = run_host(argv, env=env, cwd=work_dir, timeout_s=timeout)
    except subprocess.TimeoutExpired as exc:
        so, se = _decode(exc.output), _decode(exc.stderr)
        _write_output(out_file, so, se)
        res = ExecResult(None, so[-OUTPUT_CAP:], se[-OUTPUT_CAP:], timeout, timed_out=True)
        return Outcome(
            Kind.FAIL,
            f"timed out after {int(att.spec.timeout_s)}s (process group killed)",
            output_detail(res, header=f"output: {out_file}"),
        )
    except OSError as exc:
        return Outcome(Kind.ERROR, f"cannot execute host script {path}: {exc.strerror or exc}")
    so, se = _decode(cp.stdout), _decode(cp.stderr)
    _write_output(out_file, so, se)
    res = ExecResult(cp.returncode, so[:OUTPUT_CAP], se[:OUTPUT_CAP], 0.0)
    code = cp.returncode if cp.returncode >= 0 else None
    out = judge_exit(p, code, res.stdout, what=f"host script {path.name}")
    if cp.returncode < 0:
        out = Outcome(Kind.FAIL, f"host script {path.name} killed by signal {-cp.returncode}")
    return replace(out, detail=output_detail(res, header=f"output: {out_file}"))
