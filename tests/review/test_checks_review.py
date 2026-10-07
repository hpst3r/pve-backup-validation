"""Adversarial review tests for pbv.checks (skipped unless PBV_REVIEW=1)."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from pbv.checks import CheckEngine, default_run_host
from pbv.checks.scripts import windows_script_argv
from pbv.core import CheckContext, CheckSpec, ExecResult, InterruptedRun, OsFamily, Status
from pbv.testing.fakes import FakeGuest

REVIEW = os.environ.get("PBV_REVIEW") == "1"


def review_bug(reason: str) -> None:
    if not REVIEW:
        pytest.skip("BUG: " + reason)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s


def make_ctx(tmp_path: Path, os_: OsFamily = OsFamily.LINUX) -> CheckContext:
    return CheckContext(
        run_id="20261007T020000Z-ab12",
        target_node="restore01",
        vmid=105,
        temp_vmid=900105,
        vm_name="web01",
        os=os_,
        guest_ips=("10.99.0.5",),
        work_dir=tmp_path / "work" / "105",
        config_dir=tmp_path,
    )


def spec(ctype: str, name: str = "", *, critical: bool = True, wait_s: int = 0, timeout_s: int = 30, **params: Any):
    from pbv.config import CHECK_TYPES

    full: dict[str, Any] = {}
    for key, (_typ, _req, default) in CHECK_TYPES.get(ctype, {}).items():
        full[key] = list(default) if isinstance(default, list) else default
    full.update(params)
    return CheckSpec(
        type=ctype, name=name or f"{ctype}:x", params=full, critical=critical, timeout_s=timeout_s, wait_s=wait_s
    )


# ── run() contract: InterruptedRun → ERROR result ─────────────────────────────


class InterruptingGuest(FakeGuest):
    def exec(self, argv, *, timeout_s, input_data=None) -> ExecResult:  # type: ignore[override]
        raise InterruptedRun("stop requested")


def test_interrupted_run_on_noncritical_check_is_error_not_warn(tmp_path: Path) -> None:
    review_bug(
        "core.CheckSuite.run contract: InterruptedRun becomes an ERROR result; engine maps "
        "Kind.ERROR through spec.critical so a non-critical check reports WARN"
    )
    clock = FakeClock()
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    r = engine.run(spec("command", argv=["true"], critical=False), InterruptingGuest(), make_ctx(tmp_path))
    assert "INTERRUPTED" in r.summary
    assert r.status is Status.ERROR


# ── retry semantics: only failures are retried ────────────────────────────────


def test_warn_exit_is_not_retried_for_wait_s(tmp_path: Path) -> None:
    review_bug(
        "SPEC §5 retries only when a check fails; Kind.WARN (warn_exit / no-HTTP-client) is in RETRYABLE, "
        "so a warn_exit script is re-executed until wait_s elapses"
    )
    clock = FakeClock()
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    guest = FakeGuest()
    guest.when(lambda argv: True, ExecResult(1, "", "", 0.01))
    r = engine.run(spec("command", argv=["probe"], warn_exit=[1], wait_s=30), guest, make_ctx(tmp_path))
    assert r.status is Status.WARN
    assert r.attempts == 1, f"warn_exit command re-run {r.attempts} times"
    assert len(guest.calls) == 1


# ── host_script: escaped grandchild holding stdout hangs default_run_host ──────


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs util-linux setsid")
def test_default_run_host_bounded_when_grandchild_leaves_session(tmp_path: Path) -> None:
    review_bug(
        "scripts.default_run_host: after SIGKILL of the group it calls proc.communicate() with no "
        "timeout; a grandchild in another session that inherited stdout blocks it forever"
    )
    pidfile = tmp_path / "escaped.pid"
    script = tmp_path / "daemonize.sh"
    script.write_text(f'#!/bin/sh\nsetsid sleep 5 &\necho $! > "{pidfile}"\nsleep 5\n')
    script.chmod(0o755)
    errors: list[BaseException] = []

    def target() -> None:
        try:
            default_run_host(
                [str(script)],
                env={"PATH": os.environ.get("PATH", "")},
                cwd=tmp_path,
                timeout_s=0.2,
                grace_s=0.2,
            )
        except BaseException as exc:  # record TimeoutExpired etc.
            errors.append(exc)

    th = threading.Thread(target=target, daemon=True)
    th.start()
    try:
        th.join(1.0)
        assert not th.is_alive(), "default_run_host still blocked ~0.6s after timeout+grace"
        assert errors and isinstance(errors[0], subprocess.TimeoutExpired)
    finally:
        if pidfile.exists() and pidfile.read_text().strip():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
        th.join(2.0)


# ── Windows script wrapper: missing interpreter exits 0 ───────────────────────


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="needs pwsh to evaluate the PowerShell wrapper")
def test_windows_wrapper_missing_interpreter_is_not_exit_0() -> None:
    review_bug(
        "scripts.windows_script_argv: '& <interp> ...; exit $LASTEXITCODE' — when the interpreter is "
        "not found $LASTEXITCODE is $null and 'exit $null' exits 0, so the check PASSes"
    )
    argv = windows_script_argv("C:\\Windows\\Temp\\pbv-x-1-check.py", "pbv-no-such-interpreter.exe", [], {"A": "1"})
    assert argv[0] == "powershell.exe"
    cmd = ["pwsh", *argv[1:]]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    assert "not recognized" in r.stderr or "not recognized" in r.stdout
    assert r.returncode != 0, "wrapper exited 0 although the interpreter does not exist"
