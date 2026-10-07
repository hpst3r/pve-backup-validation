"""Service discovery and plan() mode semantics (A13)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from pbv.checks import DISCOVERY_ERROR_TYPE, LINUX_SIGNATURES, WINDOWS_SIGNATURES, CheckEngine, discover
from pbv.checks.discovery import LINUX_LIST_ARGV, parse_linux_units, parse_windows_services
from pbv.core import CheckSpec, ExecResult, OsFamily, Status, VmTarget
from pbv.testing.fakes import FakeGuest
from tests.checks.conftest import FakeClock, make_ctx, spec

LIN = OsFamily.LINUX
WIN = OsFamily.WINDOWS

UNIT_FILES = """\
apache2.service                    enabled enabled
cron.service                       enabled enabled
postgresql@.service                enabled enabled
postgresql@15-main.service         enabled enabled
mariadb.service                    enabled enabled
mysql.service                      enabled enabled
ssh.service                        enabled enabled
docker.service                     enabled enabled
cloudflared.service                enabled enabled
nginx.service                      enabled enabled
redis-server.service               enabled enabled
"""


def linux_guest(listing: str = UNIT_FILES, code: int = 0) -> FakeGuest:
    g = FakeGuest()
    g.when(lambda a: list(a) == LINUX_LIST_ARGV, ExecResult(code, listing, "", 0.1))
    return g


def windows_guest(listing: str) -> FakeGuest:
    g = FakeGuest(os=WIN)
    g.when(lambda a: "Win32_Service" in a[-1], ExecResult(0, listing, "", 0.1))
    return g


def names(specs: Sequence[CheckSpec]) -> list[str]:
    return [s.name for s in specs]


# ── parsing ────────────────────────────────────────────────────────────────────


def test_parse_linux_units_skips_templates_and_non_services() -> None:
    out = parse_linux_units(UNIT_FILES + "foo.socket enabled enabled\n\n   \n")
    assert "postgresql@" not in out and "postgresql@15-main" in out
    assert "foo" not in out and out[0] == "apache2"


def test_parse_windows_services_crlf_and_dedup() -> None:
    assert parse_windows_services("W3SVC\r\nDNS \r\n\r\nw3svc\r\n") == ["W3SVC", "DNS"]


# ── Linux discovery ────────────────────────────────────────────────────────────


def test_linux_discovery_signatures() -> None:
    specs = discover(linux_guest(), LIN)
    assert names(specs) == [
        "systemd:apache2",
        "http:80",
        "systemd:nginx",  # http:80 de-duplicated (apache2 came first)
        "systemd:postgresql@15-main",  # wildcard alternative, template skipped
        "tcp_listen:5432",
        "systemd:mariadb",  # first alternative wins; mysql not added again
        "tcp_listen:3306",
        "systemd:redis-server",
        "tcp_listen:6379",
        "systemd:docker",  # unit only
        "systemd:ssh",
        "tcp_listen:22",
        "systemd:cloudflared",
        "log_scan:cloudflared",
    ]
    by = {s.name: s for s in specs}
    assert all(s.source == "discovered" and s.critical for s in specs)
    assert by["systemd:apache2"].params == {"unit": "apache2"} and by["systemd:apache2"].only_os is LIN
    assert by["http:80"].params["port"] == 80 and by["http:80"].params["path"] == "/"
    assert by["tcp_listen:22"].params == {"port": 22} and by["tcp_listen:22"].wait_s == 60
    ls = by["log_scan:cloudflared"].params
    assert ls["unit"] == "cloudflared"
    assert ls["ignore_regex"] == "network is unreachable|no such host|dial tcp|context deadline"


def test_linux_signature_table_matches_spec() -> None:
    table = {s.names: (s.ports, s.protocol) for s in LINUX_SIGNATURES}
    assert table[("apache2", "httpd")] == ((80,), "http")
    assert table[("postgresql", "postgresql@*")] == ((5432,), "tcp")
    assert table[("docker",)] == ((), "tcp")
    assert table[("elasticsearch",)] == ((9200,), "http")
    assert table[("sshd", "ssh")] == ((22,), "tcp")
    assert table[("cloudflared",)][1] == "log_scan"
    assert len(table) == 12


def test_linux_discovery_no_matches() -> None:
    assert discover(linux_guest("cron.service enabled enabled\n"), LIN) == []


# ── Windows discovery ──────────────────────────────────────────────────────────


def test_windows_discovery_signatures() -> None:
    listing = "W3SVC\r\nntds\r\nDNS\r\nTermService\r\nLanmanServer\r\nMSSQLSERVER\r\nSpooler\r\n"
    specs = discover(windows_guest(listing), WIN)
    assert names(specs) == [
        "windows_service:W3SVC",
        "http:80",
        "windows_service:MSSQLSERVER",
        "tcp_listen:1433",
        "windows_service:ntds",  # case-insensitive match, real name kept
        "tcp_listen:389",
        "tcp_listen:88",
        "windows_service:DNS",
        "tcp_listen:53",
        "windows_service:TermService",
        "tcp_listen:3389",
        "windows_service:LanmanServer",
        "tcp_listen:445",
    ]
    assert all(s.only_os is WIN for s in specs)
    assert {s.names[0] for s in WINDOWS_SIGNATURES} == {
        "W3SVC",
        "MSSQLSERVER",
        "NTDS",
        "DNS",
        "TermService",
        "LanmanServer",
    }


# ── discovery errors (never raises) ────────────────────────────────────────────


def _single_error(specs: list[CheckSpec]) -> CheckSpec:
    assert len(specs) == 1 and specs[0].type == DISCOVERY_ERROR_TYPE
    return specs[0]


def test_discovery_agent_error() -> None:
    g = FakeGuest()
    g.alive = False
    s = _single_error(discover(g, LIN))
    assert "GUEST_AGENT_ERROR" in s.params["error"]


def test_discovery_nonzero_exit() -> None:
    g = FakeGuest()
    g.when(lambda a: True, ExecResult(1, "", "System has not been booted with systemd", 0.1))
    s = _single_error(discover(g, LIN))
    assert "exit 1" in s.params["error"] and "not been booted" in s.params["error"]


def test_discovery_timeout() -> None:
    g = FakeGuest()
    g.default = ExecResult(None, "", "", 60, timed_out=True)
    assert "timed out" in _single_error(discover(g, LIN, timeout_s=5)).params["error"]


def test_discovery_unexpected_exception() -> None:
    g = FakeGuest()

    def boom(argv, _i):
        raise RuntimeError("weird")

    g.when(lambda a: True, boom)
    assert "INTERNAL_ERROR: RuntimeError: weird" in _single_error(discover(g, LIN)).params["error"]


def test_discovery_unknown_os() -> None:
    g = FakeGuest(os=OsFamily.UNKNOWN)
    assert "OS unknown" in _single_error(discover(g, OsFamily.UNKNOWN)).params["error"]
    assert g.calls == []


def test_discovery_error_runs_as_warn(tmp_path: Path, engine: CheckEngine) -> None:
    g = FakeGuest()
    g.alive = False
    s = _single_error(discover(g, LIN))
    r = engine.run(s, FakeGuest(), make_ctx(tmp_path))
    assert r.status is Status.WARN
    assert r.summary.startswith("service discovery failed: GUEST_AGENT_ERROR")


# ── plan() modes ───────────────────────────────────────────────────────────────


def target(mode: str, checks: Sequence[CheckSpec] = ()) -> VmTarget:
    return VmTarget(vmid=105, temp_vmid=900105, mode=mode, os=None, checks=tuple(checks), boot_timeout_s=300)


EXPLICIT = (
    spec("command", "app-health", argv=["/usr/local/bin/health"]),
    spec("tcp_listen", "tcp_listen:22", port=22, wait_s=5),  # collides with discovered ssh port check
)
GLOBAL = (
    replace(spec("command", "global-ntp", argv=["chronyc", "tracking"]), source="global"),
    replace(spec("command", "app-health", argv=["dup"]), source="global"),  # duplicate name → dropped
)


def _engine(tmp_path: Path, clock: FakeClock) -> CheckEngine:
    return CheckEngine(tmp_path, GLOBAL, sleep=clock.sleep, clock=clock)


def test_plan_manual(tmp_path: Path, clock: FakeClock) -> None:
    eng = _engine(tmp_path, clock)
    g = linux_guest()
    plan = eng.plan(target("manual", EXPLICIT), g, LIN)
    assert names(plan) == ["app-health", "tcp_listen:22", "global-ntp"]
    assert plan[0].params["argv"] == ["/usr/local/bin/health"]  # first wins
    assert g.calls == []  # no discovery in manual mode
    assert eng.warnings == []


def test_plan_auto_ignores_explicit_with_warning(tmp_path: Path, clock: FakeClock) -> None:
    eng = _engine(tmp_path, clock)
    plan = eng.plan(target("auto", EXPLICIT), linux_guest("ssh.service enabled enabled\n"), LIN)
    assert names(plan) == ["systemd:ssh", "tcp_listen:22", "global-ntp", "app-health"]
    assert plan[1].source == "discovered"
    assert plan[3].source == "global"  # explicit app-health ignored, global one kept
    assert len(eng.warnings) == 1 and "ignores 2 configured check(s)" in eng.warnings[0]


def test_plan_hybrid_explicit_first_then_discovered_then_global(tmp_path: Path, clock: FakeClock) -> None:
    eng = _engine(tmp_path, clock)
    plan = eng.plan(target("hybrid", EXPLICIT), linux_guest("ssh.service enabled enabled\n"), LIN)
    assert names(plan) == ["app-health", "tcp_listen:22", "systemd:ssh", "global-ntp"]
    assert plan[1].source == "config" and plan[1].wait_s == 5  # explicit beats discovered duplicate


def test_plan_warnings_are_cleared_per_plan(tmp_path: Path, clock: FakeClock) -> None:
    eng = _engine(tmp_path, clock)
    eng.plan(target("auto", EXPLICIT), linux_guest(), LIN)
    assert eng.warnings
    eng.plan(target("manual", EXPLICIT), linux_guest(), LIN)
    assert eng.warnings == []


def test_plan_auto_nothing_discovered_warns(tmp_path: Path, clock: FakeClock) -> None:
    eng = _engine(tmp_path, clock)
    plan = eng.plan(target("auto"), linux_guest("cron.service enabled enabled\n"), LIN)
    assert names(plan) == ["global-ntp", "app-health"]
    assert any("no known services" in w for w in eng.warnings)


def test_plan_keeps_os_mismatched_checks_for_reporting(tmp_path: Path, clock: FakeClock) -> None:
    eng = CheckEngine(tmp_path, (spec("windows_service", "win-only", service="X"),), sleep=clock.sleep, clock=clock)
    plan = eng.plan(target("manual", (spec("command", "c", argv=["true"]),)), FakeGuest(), LIN)
    assert names(plan) == ["c", "win-only"]
    assert eng.run(plan[1], FakeGuest(), make_ctx(tmp_path)).status is Status.SKIPPED


def test_plan_discovery_error_included(tmp_path: Path, clock: FakeClock) -> None:
    eng = _engine(tmp_path, clock)
    g = FakeGuest()
    g.alive = False
    plan = eng.plan(target("hybrid", EXPLICIT[:1]), g, LIN)
    assert [s.type for s in plan] == ["command", DISCOVERY_ERROR_TYPE, "command"]


@pytest.mark.parametrize("mode", ["auto", "hybrid"])
def test_plan_windows_discovery(tmp_path: Path, clock: FakeClock, mode: str) -> None:
    eng = CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)
    plan = eng.plan(target(mode), windows_guest("TermService\r\n"), WIN)
    assert names(plan) == ["windows_service:TermService", "tcp_listen:3389"]
