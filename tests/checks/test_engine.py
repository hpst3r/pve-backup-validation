"""End-to-end ``CheckEngine.run`` per check type (Linux + Windows) with FakeGuest (A12)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from pbv.checks import CheckEngine
from pbv.core import (
    ApiError,
    CheckContext,
    CheckSuite,
    ExecResult,
    GuestAgentError,
    InterruptedRun,
    OsFamily,
    Status,
)
from pbv.testing.fakes import FakeGuest
from tests.checks.conftest import FakeClock, make_ctx, spec

LIN = OsFamily.LINUX
WIN = OsFamily.WINDOWS


def has(needle: str):
    return lambda argv: any(needle in a for a in argv)


def res(code: int | None = 0, out: str = "", err: str = "", timed_out: bool = False) -> ExecResult:
    return ExecResult(code, out, err, 0.01, timed_out=timed_out)


def test_engine_implements_checksuite(engine: CheckEngine) -> None:
    assert isinstance(engine, CheckSuite)


# ── systemd ────────────────────────────────────────────────────────────────────


def test_systemd_pass(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(lambda a: a[:2] == ["systemctl", "is-active"], res(0, "active\n"))
    r = engine.run(spec("systemd", "systemd:nginx", unit="nginx"), g, ctx)
    assert r.status is Status.PASS and r.attempts == 1
    assert g.calls[0][0] == ["systemctl", "is-active", "--", "nginx"]


def test_systemd_fail_collects_diagnostics(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(lambda a: a[:2] == ["systemctl", "is-active"], res(3, "failed\n"))
    g.when(lambda a: a[:2] == ["systemctl", "show"], res(0, "ActiveState=failed\nSubState=failed\nResult=exit-code\n"))
    g.when(lambda a: a[0] == "journalctl", res(0, "nginx: [emerg] bind() to 0.0.0.0:80 failed\n"))
    r = engine.run(spec("systemd", "systemd:nginx", unit="nginx"), g, ctx)
    assert r.status is Status.FAIL
    assert r.summary == "nginx is failed (ActiveState=failed SubState=failed Result=exit-code)"
    assert "bind() to 0.0.0.0:80 failed" in r.detail
    assert "journalctl -u nginx -n 15" in r.detail


def test_systemd_noncritical_fail_is_warn(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("is-active"), res(3, "inactive"))
    r = engine.run(spec("systemd", unit="x", critical=False), g, ctx)
    assert r.status is Status.WARN and r.critical is False


def test_systemd_on_windows_is_skipped(engine: CheckEngine, wctx: CheckContext) -> None:
    g = FakeGuest(os=WIN)
    r = engine.run(spec("systemd", unit="nginx"), g, wctx)
    assert r.status is Status.SKIPPED and "only on linux" in r.summary
    assert g.calls == [] and r.attempts == 0


# ── windows_service ────────────────────────────────────────────────────────────


def test_windows_service_pass_and_fail(engine: CheckEngine, wctx: CheckContext) -> None:
    g = FakeGuest(os=WIN)
    g.when(has("Get-Service"), res(0, "Running\r\n"))
    r = engine.run(spec("windows_service", service="W3SVC"), g, wctx)
    assert r.status is Status.PASS
    assert g.calls[0][0][0] == "powershell.exe"

    g2 = FakeGuest(os=WIN)
    g2.when(has("Get-Service"), res(0, "Stopped\r\n"))
    r2 = engine.run(spec("windows_service", service="W3SVC"), g2, wctx)
    assert r2.status is Status.FAIL and r2.summary == "W3SVC is Stopped"

    g3 = FakeGuest(os=WIN)
    g3.when(has("Get-Service"), res(0, "PBV_NOSERVICE\r\n"))
    r3 = engine.run(spec("windows_service", service="Nope"), g3, wctx)
    assert r3.status is Status.FAIL and "not found" in r3.summary


def test_windows_service_on_linux_is_skipped(engine: CheckEngine, ctx: CheckContext) -> None:
    r = engine.run(spec("windows_service", service="W3SVC"), FakeGuest(), ctx)
    assert r.status is Status.SKIPPED


# ── tcp_listen ─────────────────────────────────────────────────────────────────


def test_tcp_listen_linux(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("ss -ltn"), res(0, "PBV_TOOL ss\nLISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n"))
    assert engine.run(spec("tcp_listen", port=2222), g, ctx).status is Status.PASS
    r = engine.run(spec("tcp_listen", port=22), g, ctx)
    assert r.status is Status.FAIL and r.summary == "no TCP listener on port 22"
    assert "0.0.0.0:2222" in r.detail


def test_tcp_listen_linux_no_tool(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("ss -ltn"), res(0, "PBV_NOTOOL\n"))
    r = engine.run(spec("tcp_listen", port=22), g, ctx)
    assert r.status is Status.FAIL and "neither ss nor netstat" in r.summary


def test_tcp_listen_windows(engine: CheckEngine, wctx: CheckContext) -> None:
    g = FakeGuest(os=WIN)
    g.when(has("-LocalPort 3389"), res(0, "PBV_COUNT 1\r\n"))
    g.when(has("-LocalPort 445"), res(0, "PBV_COUNT 0\r\n"))
    g.when(has("-LocalPort 135"), res(0, "PBV_NETSTAT\r\n  TCP    0.0.0.0:135   0.0.0.0:0   LISTENING\r\n"))
    assert engine.run(spec("tcp_listen", port=3389), g, wctx).status is Status.PASS
    assert engine.run(spec("tcp_listen", port=445), g, wctx).status is Status.FAIL
    assert engine.run(spec("tcp_listen", port=135), g, wctx).status is Status.PASS


# ── http ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("stdout", "params", "status"),
    [
        ("PBV_HTTP 200\n", {}, Status.PASS),
        ("PBV_HTTP 302\n", {}, Status.PASS),
        ("PBV_HTTP 401\n", {}, Status.PASS),
        ("PBV_HTTP 404\n", {}, Status.FAIL),
        ("PBV_HTTP 503\n", {}, Status.FAIL),
        ("PBV_HTTP 000\n", {}, Status.FAIL),
        ("PBV_HTTP 404\n", {"expect_status": [404]}, Status.PASS),
        ("PBV_HTTP 200\n", {"expect_status": [204]}, Status.FAIL),
        ("PBV_HTTP 200\nPBV_BODY\n<h1>Welcome</h1>", {"body_regex": "Welcome"}, Status.PASS),
        ("PBV_HTTP 200\nPBV_BODY\n<h1>Oops</h1>", {"body_regex": "Welcome"}, Status.FAIL),
    ],
)
@pytest.mark.parametrize("os", [LIN, WIN])
def test_http(tmp_path: Path, clock: FakeClock, os: OsFamily, stdout: str, params: dict, status: Status) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest(os=os)
    out = stdout.replace("\n", "\r\n") if os is WIN else stdout
    g.when(has("PBV_HTTP"), res(0, out))
    r = engine.run(spec("http", port=80, **params), g, make_ctx(tmp_path, os))
    assert r.status is status, r.summary
    if os is WIN:
        assert "Invoke-WebRequest" in g.calls[0][0][-1]
    else:
        assert g.calls[0][0][:2] == ["/bin/sh", "-c"]


def test_http_windows_connection_error_summary(engine: CheckEngine, wctx: CheckContext) -> None:
    g = FakeGuest(os=WIN)
    g.when(has("Invoke-WebRequest"), res(0, "PBV_HTTP_ERR Unable to connect to the remote server\r\nPBV_HTTP 0\r\n"))
    r = engine.run(spec("http", port=80), g, wctx)
    assert r.status is Status.FAIL
    assert r.summary == "http://127.0.0.1:80/: no response (Unable to connect to the remote server)"


def test_http_no_client_falls_back_to_tcp_warn(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("PBV_NOCLIENT"), res(0, "PBV_NOCLIENT\n"))
    g.when(has("ss -ltn"), res(0, "PBV_TOOL ss\nLISTEN 0 128 *:80 *:*\n"))
    r = engine.run(spec("http", port=80), g, ctx)
    assert r.status is Status.WARN
    assert r.summary == "no HTTP client in guest; port 80 listening"


def test_http_no_client_and_port_closed_fails(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("PBV_NOCLIENT"), res(0, "PBV_NOCLIENT\n"))
    g.when(has("ss -ltn"), res(0, "PBV_TOOL ss\n"))
    r = engine.run(spec("http", port=80), g, ctx)
    assert r.status is Status.FAIL and "no HTTP client" in r.summary


# ── command ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("os", [LIN, WIN])
@pytest.mark.parametrize(
    ("code", "out", "params", "critical", "status"),
    [
        (0, "", {}, True, Status.PASS),
        (1, "", {}, True, Status.FAIL),
        (1, "", {}, False, Status.WARN),
        (2, "", {"expect_exit": [0, 2]}, True, Status.PASS),
        (3, "", {"warn_exit": [3]}, True, Status.WARN),
        (0, "status: OK\r\n", {"stdout_regex": r"status: OK"}, True, Status.PASS),
        (0, "status: DEGRADED\r\n", {"stdout_regex": r"status: OK"}, True, Status.FAIL),
    ],
)
def test_command(
    tmp_path: Path,
    clock: FakeClock,
    os: OsFamily,
    code: int,
    out: str,
    params: dict,
    critical: bool,
    status: Status,
) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest(os=os)
    argv = ["cmd.exe", "/c", "ver"] if os is WIN else ["/usr/bin/test", "-f", "/etc/hostname"]
    g.when(lambda a: list(a) == argv, res(code, out, "some stderr"))
    r = engine.run(spec("command", argv=argv, critical=critical, **params), g, make_ctx(tmp_path, os))
    assert r.status is status, r.summary
    assert g.calls[0][0] == argv  # run directly, no shell wrapper
    assert f"exit={code}" in r.detail


def test_command_timeout(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("sleep"), res(None, timed_out=True))
    r = engine.run(spec("command", argv=["sleep", "999"], timeout_s=7), g, ctx)
    assert r.status is Status.FAIL
    assert r.summary == "timed out after 7s (guest process may still be running)"
    assert g.calls[0][1] == 7  # the exec was bounded by the per-attempt timeout


def test_command_timeout_noncritical_is_warn(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.default = res(None, timed_out=True)
    r = engine.run(spec("command", argv=["x"], critical=False), g, ctx)
    assert r.status is Status.WARN and "timed out" in r.summary


def test_command_killed_without_exit_code(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.default = res(None)
    r = engine.run(spec("command", argv=["x"]), g, ctx)
    assert r.status is Status.FAIL and "without an exit code" in r.summary


# ── log_scan ───────────────────────────────────────────────────────────────────


def test_log_scan(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("--since"), res(0, "ok line\nERROR one\nfatal two\nfine\n"))
    r = engine.run(spec("log_scan", unit="app", max_matches=1), g, ctx)
    assert r.status is Status.FAIL and r.summary == "app: 2 error line(s) since '5 min ago' (max 1)"
    assert r.detail == "ERROR one\nfatal two"
    assert g.calls[0][0] == ["journalctl", "--unit", "app", "--since", "5 min ago", "--no-pager", "-o", "cat"]
    r2 = engine.run(spec("log_scan", unit="app", max_matches=2), g, ctx)
    assert r2.status is Status.PASS
    r3 = engine.run(spec("log_scan", unit="app", ignore_regex="fatal|ERROR"), g, ctx)
    assert r3.status is Status.PASS


def test_log_scan_journalctl_failure(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("journalctl"), res(1, "", "No journal files were found."))
    r = engine.run(spec("log_scan", unit="app"), g, ctx)
    assert r.status is Status.FAIL and "journalctl for app failed" in r.summary


def test_log_scan_on_windows_skipped(engine: CheckEngine, wctx: CheckContext) -> None:
    assert engine.run(spec("log_scan", unit="app"), FakeGuest(os=WIN), wctx).status is Status.SKIPPED


# ── OS handling ────────────────────────────────────────────────────────────────


def test_only_os_mismatch_skips(engine: CheckEngine, wctx: CheckContext, ctx: CheckContext) -> None:
    from dataclasses import replace

    s = replace(spec("command", argv=["true"]), only_os=LIN)
    g = FakeGuest(os=WIN)
    r = engine.run(s, g, wctx)
    assert r.status is Status.SKIPPED and r.summary == "only on linux (guest is windows)"
    assert g.calls == []
    assert engine.run(s, FakeGuest(), ctx).status is Status.PASS


@pytest.mark.parametrize("ctype", ["tcp_listen", "http", "script", "systemd", "windows_service", "log_scan"])
def test_unknown_os_skips_os_specific_checks(engine: CheckEngine, tmp_path: Path, ctype: str) -> None:
    params = {
        "tcp_listen": {"port": 22},
        "http": {"port": 80},
        "script": {"path": "/x.sh"},
        "systemd": {"unit": "x"},
        "windows_service": {"service": "x"},
        "log_scan": {"unit": "x"},
    }[ctype]
    g = FakeGuest(os=OsFamily.UNKNOWN)
    r = engine.run(spec(ctype, **params), g, make_ctx(tmp_path, OsFamily.UNKNOWN))
    assert r.status is Status.SKIPPED and "OS unknown" in r.summary
    assert g.calls == []


def test_unknown_os_still_runs_command(engine: CheckEngine, tmp_path: Path) -> None:
    r = engine.run(spec("command", argv=["true"]), FakeGuest(os=OsFamily.UNKNOWN), make_ctx(tmp_path, OsFamily.UNKNOWN))
    assert r.status is Status.PASS


# ── retries (wait_s) ───────────────────────────────────────────────────────────


def _flaky(fail_times: int, ok: ExecResult, bad: ExecResult):
    calls = {"n": 0}

    def handler(argv: Sequence[str], _input: bytes | None) -> ExecResult:
        calls["n"] += 1
        return bad if calls["n"] <= fail_times else ok

    return handler, calls


def test_wait_s_retries_until_pass(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock, retry_interval_s=3.0)
    g = FakeGuest()
    handler, calls = _flaky(3, res(0, "active"), res(3, "activating"))
    g.when(has("is-active"), handler)
    r = engine.run(spec("systemd", unit="db", wait_s=60), g, ctx)
    assert r.status is Status.PASS
    assert r.attempts == 4 and calls["n"] == 4
    assert clock.sleeps == [3.0, 3.0, 3.0]
    assert r.duration_s == pytest.approx(9.0)


def test_wait_s_gives_up_after_deadline(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock, retry_interval_s=3.0)
    g = FakeGuest()
    g.when(has("is-active"), res(3, "inactive"))
    r = engine.run(spec("systemd", unit="db", wait_s=10), g, ctx)
    assert r.status is Status.FAIL
    # attempts at t=0,3,6,9 (9 < 10 → retry), t=12 ≥ 10 → stop
    assert r.attempts == 5 and len(clock.sleeps) == 4


def test_no_retry_without_wait_s(engine: CheckEngine, clock: FakeClock, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("is-active"), res(3, "inactive"))
    r = engine.run(spec("systemd", unit="db"), g, ctx)
    assert r.attempts == 1 and clock.sleeps == []


def test_should_stop_ends_retries(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    stop = {"flag": False}
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock, should_stop=lambda: stop["flag"])
    g = FakeGuest()

    def handler(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        stop["flag"] = True
        return res(3, "inactive")

    g.when(has("is-active"), handler)
    r = engine.run(spec("systemd", unit="db", wait_s=600), g, ctx)
    assert r.attempts == 1 and r.status is Status.FAIL


def test_timeout_is_retried_within_wait_s(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest()
    handler, _ = _flaky(1, res(0), res(None, timed_out=True))
    g.when(has("probe"), handler)
    r = engine.run(spec("command", argv=["probe"], wait_s=30), g, ctx)
    assert r.status is Status.PASS and r.attempts == 2


# ── agent errors ───────────────────────────────────────────────────────────────


def test_agent_error_critical_is_error(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.alive = False
    r = engine.run(spec("systemd", unit="nginx"), g, ctx)
    assert r.status is Status.ERROR
    assert r.summary.startswith("GUEST_AGENT_ERROR:") and "not running" in r.summary


def test_agent_error_noncritical_is_warn(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.alive = False
    r = engine.run(spec("command", argv=["x"], critical=False), g, ctx)
    assert r.status is Status.WARN and "GUEST_AGENT_ERROR" in r.summary


def test_api_error_is_agent_error_and_retried(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest()
    n = {"c": 0}

    def handler(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        n["c"] += 1
        if n["c"] == 1:
            raise ApiError("QEMU guest agent is not running", status=500)
        return res(0, "active")

    g.when(has("is-active"), handler)
    r = engine.run(spec("systemd", unit="x", wait_s=30), g, ctx)
    assert r.status is Status.PASS and r.attempts == 2


def test_agent_error_retried_then_error(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest()
    g.alive = False
    r = engine.run(spec("systemd", unit="x", wait_s=6), g, ctx)
    assert r.status is Status.ERROR and r.attempts == 3


def test_diagnostic_agent_error_does_not_mask_failure(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.when(has("is-active"), res(3, "failed"))

    def boom(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        raise GuestAgentError("agent hiccup")

    g.when(lambda a: True, boom)
    r = engine.run(spec("systemd", unit="x"), g, ctx)
    assert r.status is Status.FAIL and r.summary == "x is failed"


# ── boundary behaviour ─────────────────────────────────────────────────────────


def test_unexpected_exception_becomes_internal_error(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()

    def boom(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        raise ValueError("kaboom")

    g.when(lambda a: True, boom)
    r = engine.run(spec("command", argv=["x"], wait_s=60), g, ctx)
    assert r.status is Status.ERROR and r.summary == "INTERNAL_ERROR: ValueError: kaboom"
    assert r.attempts == 1  # not retried


def test_interrupted_guest_is_not_retried(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()

    def interrupted(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        raise InterruptedRun("signal received")

    g.when(lambda a: True, interrupted)
    r = engine.run(spec("command", argv=["x"], wait_s=60), g, ctx)
    assert r.status is Status.ERROR and r.summary.startswith("INTERRUPTED") and r.attempts == 1


def test_interrupted_noncritical_check_stays_error(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()

    def interrupted(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        raise InterruptedRun("signal received")

    g.when(lambda a: True, interrupted)
    r = engine.run(spec("command", argv=["x"], critical=False, wait_s=60), g, ctx)
    assert r.status is Status.ERROR and r.summary.startswith("INTERRUPTED") and r.attempts == 1


def test_internal_error_noncritical_check_stays_error(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()

    def boom(argv: Sequence[str], _i: bytes | None) -> ExecResult:
        raise ValueError("kaboom")

    g.when(lambda a: True, boom)
    r = engine.run(spec("command", argv=["x"], critical=False), g, ctx)
    assert r.status is Status.ERROR and r.summary.startswith("INTERNAL_ERROR")


def test_warn_exit_is_final_not_retried(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest()
    g.default = res(1)
    r = engine.run(spec("command", argv=["probe"], warn_exit=[1], wait_s=30), g, ctx)
    assert r.status is Status.WARN and r.attempts == 1 and len(g.calls) == 1
    assert clock.sleeps == []


def test_http_no_client_warn_is_not_retried(tmp_path: Path, clock: FakeClock, ctx: CheckContext) -> None:
    engine = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    g = FakeGuest()
    g.when(has("PBV_NOCLIENT"), res(0, "PBV_NOCLIENT\n"))
    g.when(has("ss -ltn"), res(0, "PBV_TOOL ss\nLISTEN 0 128 *:80 *:*\n"))
    r = engine.run(spec("http", port=80, wait_s=30), g, ctx)
    assert r.status is Status.WARN and r.attempts == 1 and clock.sleeps == []


def test_unknown_type_is_error(engine: CheckEngine, ctx: CheckContext) -> None:
    from pbv.core import CheckSpec

    r = engine.run(CheckSpec(type="bogus", name="b"), FakeGuest(), ctx)
    assert r.status is Status.ERROR and "unknown check type" in r.summary


def test_summary_single_line_and_detail_capped(engine: CheckEngine, ctx: CheckContext) -> None:
    g = FakeGuest()
    g.default = res(1, "line\r\n" * 5000, "err " * 5000)
    r = engine.run(spec("command", argv=["x" * 300]), g, ctx)
    assert "\n" not in r.summary and len(r.summary) <= 200
    assert len(r.detail.encode()) <= 8192 and r.detail.startswith("[…truncated ")


def test_result_metadata(engine: CheckEngine, ctx: CheckContext) -> None:
    from dataclasses import replace

    s = replace(spec("command", "my-check", argv=["true"], critical=False), source="global")
    r = engine.run(s, FakeGuest(), ctx)
    assert (r.name, r.type, r.critical, r.source) == ("my-check", "command", False, "global")
