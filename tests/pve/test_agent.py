"""PveGuestAgent against FakePve."""

from __future__ import annotations

from typing import Any

import pytest

from pbv.core import ApiError, ExecStatus, GuestAgent, GuestAgentError, OsFamily
from pbv.pve import PveGuestAgent
from pbv.testing.fakes import FakePve, GuestProfile

from .conftest import FakeClock

VMID = 900105


@pytest.fixture
def pve() -> FakePve:
    p = FakePve()
    p.add_vm(VMID, status="running")
    p.guest_profile[VMID] = GuestProfile()
    return p


def agent(pve: Any, clock: FakeClock, poll_s: float = 1.0) -> PveGuestAgent:
    return PveGuestAgent(pve, VMID, sleep=clock.sleep, clock=clock, poll_s=poll_s)


def test_implements_protocol(pve: FakePve, clock: FakeClock) -> None:
    assert isinstance(agent(pve, clock), GuestAgent)


def test_ping(pve: FakePve, clock: FakeClock) -> None:
    assert agent(pve, clock).ping() is True
    pve.vms[VMID].status = "stopped"
    with pytest.raises(GuestAgentError, match="is not running"):
        agent(pve, clock).ping()


def test_exec_success_after_polls(pve: FakePve, clock: FakeClock) -> None:
    prof = pve.guest_profile[VMID]
    prof.exec_polls = 2
    prof.on_exec = lambda argv, data: (3, "out\n", "err\n")
    res = agent(pve, clock, poll_s=0.5).exec(["systemctl", "is-active", "x"], timeout_s=10, input_data=b"in")
    assert res.exitcode == 3
    assert (res.stdout, res.stderr) == ("out\n", "err\n")
    assert res.timed_out is False
    assert res.duration_s == pytest.approx(1.0)
    assert clock.sleeps == [0.5, 0.5]
    assert pve.vms[VMID].exec_calls == [(["systemctl", "is-active", "x"], b"in")]


def test_exec_timeout(pve: FakePve, clock: FakeClock) -> None:
    pve.guest_profile[VMID].exec_polls = 1000
    res = agent(pve, clock, poll_s=1.0).exec(["sleep", "999"], timeout_s=2.5)
    assert res.timed_out is True
    assert res.exitcode is None
    assert clock.sleeps == [1.0, 1.0, 0.5]


def test_exec_agent_error_becomes_guest_agent_error(pve: FakePve, clock: FakeClock) -> None:
    pve.guest_profile[VMID].never_boots = True
    with pytest.raises(GuestAgentError, match="QEMU guest agent is not running"):
        agent(pve, clock).exec(["true"], timeout_s=5)


class _StatusApi(FakePve):
    """FakePve whose exec-status returns a scripted ExecStatus."""

    def __init__(self, status: ExecStatus) -> None:
        super().__init__()
        self._status = status

    def agent_exec_status(self, vmid: int, pid: int) -> ExecStatus:
        return self._status


def test_exec_truncated_and_signal(clock: FakeClock) -> None:
    api = _StatusApi(ExecStatus(exited=True, exitcode=None, stdout="x", err_truncated=True, signal=9))
    api.add_vm(VMID, status="running")
    res = agent(api, clock).exec(["x"], timeout_s=5)
    assert res.exitcode is None
    assert res.truncated is True
    assert res.timed_out is False


def test_write_file(pve: FakePve, clock: FakeClock) -> None:
    agent(pve, clock).write_file("/tmp/a.sh", b"echo hi\n")
    assert pve.guest_profile[VMID].files == {"/tmp/a.sh": b"echo hi\n"}
    pve.fail_next["agent_file_write"] = ApiError("file-write failed: disk full", status=500)
    with pytest.raises(GuestAgentError, match="disk full"):
        agent(pve, clock).write_file("/tmp/b", b"")


@pytest.mark.parametrize(
    ("os", "expected"),
    [(OsFamily.WINDOWS, OsFamily.WINDOWS), (OsFamily.LINUX, OsFamily.LINUX), (OsFamily.UNKNOWN, OsFamily.UNKNOWN)],
)
def test_os_family(pve: FakePve, clock: FakeClock, os: OsFamily, expected: OsFamily) -> None:
    pve.guest_profile[VMID].os = os
    assert agent(pve, clock).os_family() == expected


def test_os_family_unknown_on_error(pve: FakePve, clock: FakeClock) -> None:
    pve.fail_next["agent_osinfo"] = ApiError("command not supported", status=500)
    assert agent(pve, clock).os_family() == OsFamily.UNKNOWN


def test_ip_addresses_filter_order_dedupe(pve: FakePve, clock: FakeClock) -> None:
    pve.guest_profile[VMID].ips = [
        "fd00::5",
        "10.99.0.5",
        "169.254.3.4",
        "fe80::1",
        "127.0.0.2",
        "::1",
        "10.99.0.6",
        "10.99.0.5",
        "fd00::5",
    ]
    assert agent(pve, clock).ip_addresses() == ["10.99.0.5", "10.99.0.6", "fd00::5"]


def test_ip_addresses_empty_on_error(pve: FakePve, clock: FakeClock) -> None:
    pve.guest_profile[VMID].never_boots = True
    assert agent(pve, clock).ip_addresses() == []


def test_ip_addresses_ignores_garbage() -> None:
    class Api(FakePve):
        def agent_network_interfaces(self, vmid: int) -> list[dict[str, Any]]:
            return [
                {"name": "lo", "ip-addresses": [{"ip-address": "10.0.0.1"}]},
                {"name": "eth0", "ip-addresses": [{"ip-address": "bogus"}, {"ip-address": "fe80::2%eth0"}]},
                {"name": "eth1"},
                {"name": "eth2", "ip-addresses": [{"ip-address": "192.0.2.7"}]},
            ]

    assert PveGuestAgent(Api(), VMID).ip_addresses() == ["192.0.2.7"]
