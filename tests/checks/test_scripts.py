"""``script`` (guest upload + exec) and ``host_script`` (runner subprocess) checks (A12)."""

from __future__ import annotations

import functools
import os
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from pbv.checks import CheckEngine, default_run_host
from pbv.core import CheckContext, ExecResult, OsFamily, Status
from pbv.testing.fakes import FakeGuest
from tests.checks.conftest import FakeClock, make_ctx, spec

RID = "20261007T020000Z-ab12"


def res(code: int | None = 0, out: str = "", err: str = "", timed_out: bool = False) -> ExecResult:
    return ExecResult(code, out, err, 0.01, timed_out=timed_out)


def _env_from_argv(argv: Sequence[str]) -> dict[str, str]:
    env = {}
    for a in argv[1:]:
        if "=" not in a or a.startswith("/"):
            break
        k, _, v = a.partition("=")
        env[k] = v
    return env


# ── guest script: Linux ────────────────────────────────────────────────────────


def test_linux_script_upload_path_env_and_cleanup(tmp_path: Path, engine: CheckEngine, ctx: CheckContext) -> None:
    src = tmp_path / "check db.sh"
    src.write_bytes(b"#!/bin/sh\necho ok\n")
    g = FakeGuest()
    g.when(lambda a: a[0] == "/usr/bin/env", res(0, "db OK\n"))
    s = spec("script", "script:check db.sh", path=str(src), args=["--fast"], env={"MODE": "x; rm -rf /"})
    r = engine.run(s, g, ctx)
    assert r.status is Status.PASS, r.summary

    dest = f"/tmp/pbv-{RID}-1-check_db.sh"
    assert g.files == {dest: b"#!/bin/sh\necho ok\n"}
    run_argv, run_timeout, _ = g.calls[0]
    assert run_argv[-3:] == ["/bin/sh", dest, "--fast"]
    assert run_timeout == 30
    env = _env_from_argv(run_argv)
    assert env == {
        "PBV_RUN_ID": RID,
        "PBV_VMID": "105",
        "PBV_TEMP_VMID": "900105",
        "PBV_VM_NAME": "web01",
        "PBV_OS": "linux",
        "PBV_GUEST_IPS": "10.99.0.5,fd00::5",
        "PBV_GUEST_IP": "10.99.0.5",
        "PBV_TARGET_NODE": "restore01",
        "PBV_CHECK_NAME": "script:check db.sh",
        "MODE": "x; rm -rf /",  # one argv element, never a shell
    }
    assert "PBV_WORK_DIR" not in env
    assert g.calls[1][0] == ["rm", "-f", "--", dest]  # best-effort cleanup
    assert f"guest path {dest}" in r.detail


def test_script_counter_increments_per_engine(tmp_path: Path, engine: CheckEngine, ctx: CheckContext) -> None:
    src = tmp_path / "s.sh"
    src.write_text("true\n")
    g = FakeGuest()
    engine.run(spec("script", path=str(src)), g, ctx)
    engine.run(spec("script", path=str(src)), g, ctx)
    assert sorted(g.files) == [f"/tmp/pbv-{RID}-1-s.sh", f"/tmp/pbv-{RID}-2-s.sh"]


def test_linux_script_custom_interpreter_and_exit_mapping(
    tmp_path: Path, engine: CheckEngine, ctx: CheckContext
) -> None:
    src = tmp_path / "probe.py"
    src.write_text("print('hi')\n")
    g = FakeGuest()
    g.when(lambda a: a[0] == "/usr/bin/env", res(3, "degraded\n"))
    r = engine.run(spec("script", path=str(src), interpreter="/usr/bin/python3 -u", warn_exit=[3]), g, ctx)
    assert r.status is Status.WARN and "warn_exit" in r.summary
    assert g.calls[0][0][-3:] == ["/usr/bin/python3", "-u", f"/tmp/pbv-{RID}-1-probe.py"]

    g2 = FakeGuest()
    g2.when(lambda a: a[0] == "/usr/bin/env", res(1, ""))
    assert engine.run(spec("script", path=str(src)), g2, ctx).status is Status.FAIL
    assert engine.run(spec("script", path=str(src), critical=False), g2, ctx).status is Status.WARN

    g3 = FakeGuest()
    g3.when(lambda a: a[0] == "/usr/bin/env", res(0, "nope\n"))
    r3 = engine.run(spec("script", path=str(src), stdout_regex="^all good"), g3, ctx)
    assert r3.status is Status.FAIL and "did not match" in r3.summary


def test_script_relative_path_resolves_against_config_dir(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "rel.sh").write_text("true\n")
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest()
    assert engine.run(spec("script", path="scripts/rel.sh"), g, ctx).status is Status.PASS
    assert f"/tmp/pbv-{RID}-1-rel.sh" in g.files


def test_script_missing_file_is_error_not_retried(engine: CheckEngine, clock: FakeClock, ctx: CheckContext) -> None:
    g = FakeGuest()
    r = engine.run(spec("script", path="/nonexistent/x.sh", wait_s=60), g, ctx)
    assert r.status is Status.ERROR and "cannot read script" in r.summary
    assert r.attempts == 1 and g.calls == [] and clock.sleeps == []


def test_script_bad_env_name_is_error(tmp_path: Path, engine: CheckEngine, ctx: CheckContext) -> None:
    src = tmp_path / "s.sh"
    src.write_text("true\n")
    r = engine.run(spec("script", path=str(src), env={"A=B": "x"}), FakeGuest(), ctx)
    assert r.status is Status.ERROR and "invalid environment variable" in r.summary


def test_script_timeout_still_cleans_up(tmp_path: Path, engine: CheckEngine, ctx: CheckContext) -> None:
    src = tmp_path / "slow.sh"
    src.write_text("sleep 999\n")
    g = FakeGuest()
    g.when(lambda a: a[0] == "/usr/bin/env", res(None, timed_out=True))
    r = engine.run(spec("script", path=str(src), timeout_s=5), g, ctx)
    assert r.status is Status.FAIL and r.summary == "timed out after 5s (guest process may still be running)"
    assert g.calls[-1][0][:3] == ["rm", "-f", "--"]


def test_script_upload_agent_failure_is_agent_error(tmp_path: Path, engine: CheckEngine, ctx: CheckContext) -> None:
    src = tmp_path / "s.sh"
    src.write_text("true\n")
    g = FakeGuest()
    g.alive = False
    r = engine.run(spec("script", path=str(src)), g, ctx)
    assert r.status is Status.ERROR and r.summary.startswith("GUEST_AGENT_ERROR")


def test_script_cleanup_failure_is_ignored(tmp_path: Path, engine: CheckEngine, ctx: CheckContext) -> None:
    from pbv.core import GuestAgentError

    src = tmp_path / "s.sh"
    src.write_text("true\n")
    g = FakeGuest()

    def rm_fails(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        raise GuestAgentError("agent went away")

    g.when(lambda a: a[0] == "rm", rm_fails)
    assert engine.run(spec("script", path=str(src)), g, ctx).status is Status.PASS


# ── guest script: Windows ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "expect_dest", "expect_call"),
    [
        (
            "check.ps1",
            "check.ps1",
            "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '{dest}'",
        ),
        ("check.cmd", "check.cmd", "& cmd.exe /c '{dest}'"),
        ("check.bat", "check.bat", "& cmd.exe /c '{dest}'"),
        (
            "check.txt",
            "check.txt.ps1",
            "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '{dest}'",
        ),
    ],
)
def test_windows_script_by_extension(
    tmp_path: Path, clock: FakeClock, name: str, expect_dest: str, expect_call: str
) -> None:
    src = tmp_path / name
    src.write_bytes(b"Write-Output ok\r\n")
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest(os=OsFamily.WINDOWS)
    g.when(lambda a: "exit $LASTEXITCODE" in a[-1], res(0, "ok\r\n"))
    r = engine.run(spec("script", path=str(src), args=["it's"]), g, make_ctx(tmp_path, OsFamily.WINDOWS))
    assert r.status is Status.PASS, r.summary
    dest = f"C:\\Windows\\Temp\\pbv-{RID}-1-{expect_dest}"
    assert g.files == {dest: b"Write-Output ok\r\n"}
    script = g.calls[0][0][-1]
    assert g.calls[0][0][0] == "powershell.exe"
    assert expect_call.format(dest=dest) + " 'it''s'; exit $LASTEXITCODE" in script
    assert "$env:PBV_OS = 'windows'; " in script
    assert "$env:PBV_GUEST_IPS = '10.99.0.5,fd00::5'; " in script
    assert "Remove-Item -LiteralPath" in g.calls[1][0][-1]


# ── host_script ────────────────────────────────────────────────────────────────


def _host_script(tmp_path: Path, body: str, name: str = "host.sh") -> Path:
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return p


def _host_engine(tmp_path: Path, clock: FakeClock, grace_s: float = 0.3, **kw) -> CheckEngine:
    return CheckEngine(
        tmp_path,
        sleep=clock.sleep,
        clock=clock,
        run_host=functools.partial(default_run_host, grace_s=grace_s),
        **kw,
    )


def test_host_script_env_cwd_and_output(
    tmp_path: Path, clock: FakeClock, ctx: CheckContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PBV_TEST_SECRET", "must-not-leak")
    monkeypatch.setenv("LANG", "C.UTF-8")
    script = _host_script(tmp_path, 'env | sort\necho "cwd=$(pwd)"\necho to-stderr >&2\nexit 0\n')
    engine = _host_engine(tmp_path, clock, host_env={"SSH_AUTH_SOCK": "/run/agent"})
    s = spec("host_script", "host: ping", path=str(script), args=["a b"], env={"EXTRA": "1"})
    r = engine.run(s, FakeGuest(), ctx)
    assert r.status is Status.PASS, r.detail
    out_file = ctx.work_dir / "host_ping.out"
    text = out_file.read_text()
    env = dict(ln.split("=", 1) for ln in text.split("--- stderr ---")[0].splitlines() if "=" in ln)
    assert env["PBV_WORK_DIR"] == str(ctx.work_dir)
    assert env["PBV_TEMP_VMID"] == "900105" and env["PBV_CHECK_NAME"] == "host: ping"
    assert env["SSH_AUTH_SOCK"] == "/run/agent" and env["EXTRA"] == "1" and env["LANG"] == "C.UTF-8"
    assert "PBV_TEST_SECRET" not in env  # only PATH/LANG/HOME are inherited
    assert env["cwd"] == str(ctx.work_dir)
    assert "to-stderr" in text
    assert str(out_file) in r.detail


@pytest.mark.parametrize(
    ("code", "params", "critical", "status"),
    [
        (0, {}, True, Status.PASS),
        (1, {}, True, Status.FAIL),
        (1, {}, False, Status.WARN),
        (4, {"warn_exit": [4]}, True, Status.WARN),
        (4, {"expect_exit": [4]}, True, Status.PASS),
    ],
)
def test_host_script_exit_mapping(
    tmp_path: Path, clock: FakeClock, ctx: CheckContext, code: int, params: dict, critical: bool, status: Status
) -> None:
    script = _host_script(tmp_path, f"exit {code}\n")
    r = _host_engine(tmp_path, clock).run(
        spec("host_script", path=str(script), critical=critical, **params), FakeGuest(), ctx
    )
    assert r.status is status, r.summary


def test_host_script_not_executable_is_error(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    p = tmp_path / "noexec.sh"
    p.write_text("#!/bin/sh\nexit 0\n")
    p.chmod(0o644)
    r = _host_engine(tmp_path, clock).run(spec("host_script", path=str(p), wait_s=60), FakeGuest(), ctx)
    assert r.status is Status.ERROR and "cannot execute host script" in r.summary
    assert r.attempts == 1


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a reaped-later zombie counts as dead
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


def test_host_script_timeout_kills_process_group(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    pidfile = tmp_path / "child.pid"
    # The leader ignores SIGTERM, and so does its background child (inherited disposition),
    # so only the SIGKILL to the whole group after the grace period can end them.
    script = _host_script(tmp_path, f"trap '' TERM\nsleep 30 &\necho $! > {pidfile}\necho started\nwait\n")
    engine = _host_engine(tmp_path, clock, grace_s=0.3)
    t0 = time.monotonic()
    r = engine.run(spec("host_script", "slow", path=str(script), timeout_s=1), FakeGuest(), ctx)
    elapsed = time.monotonic() - t0
    assert r.status is Status.FAIL
    assert r.summary == "timed out after 1s (process group killed)"
    assert elapsed < 3
    child = int(pidfile.read_text())
    deadline = time.monotonic() + 1
    while _pid_alive(child) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _pid_alive(child)
    assert "started" in (ctx.work_dir / "slow.out").read_text()


def test_default_run_host_sigterm_suffices(tmp_path: Path) -> None:
    script = _host_script(tmp_path, "sleep 30\n")
    t0 = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        default_run_host([str(script)], env={"PATH": os.environ.get("PATH", "")}, cwd=tmp_path, timeout_s=0.3)
    assert time.monotonic() - t0 < 2  # did not wait for the 5 s grace period


def test_host_script_injected_runner_and_signal_death(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    seen = {}

    def fake_run(argv, *, env, cwd, timeout_s):
        seen.update(argv=argv, timeout_s=timeout_s, cwd=cwd)
        return subprocess.CompletedProcess(argv, -9, b"partial", b"")

    script = _host_script(tmp_path, "exit 0\n")
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock, run_host=fake_run)
    r = engine.run(spec("host_script", path=str(script), args=["x"], timeout_s=12), FakeGuest(), ctx)
    assert r.status is Status.FAIL and "killed by signal 9" in r.summary
    assert seen == {"argv": [str(script), "x"], "timeout_s": 12, "cwd": ctx.work_dir}


def test_host_script_runs_on_any_os(tmp_path: Path, clock: FakeClock) -> None:
    script = _host_script(tmp_path, "exit 0\n")
    for os_family in (OsFamily.WINDOWS, OsFamily.UNKNOWN):
        r = _host_engine(tmp_path, clock).run(
            spec("host_script", path=str(script)), FakeGuest(os=os_family), make_ctx(tmp_path, os_family)
        )
        assert r.status is Status.PASS
