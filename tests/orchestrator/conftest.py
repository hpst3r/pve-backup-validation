"""Shared fixtures for orchestrator tests: config builder, fake clock, guest adapter, runner factory."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from pbv.config import Config, parse_config
from pbv.core import BackupRef, ExecResult, OsFamily
from pbv.orchestrator import Runner
from pbv.testing.fakes import FakeCheckSuite, FakeConsole, FakeNodeShell, FakePve, RecordingNotifier

NOW_CTIME = 1_790_000_000


def make_cfg(tmp_path: Path, *, vms: Sequence[dict[str, Any]] = ({"vmid": 105},), **sections: dict[str, Any]) -> Config:
    """Build a validated Config; keyword args override/extend whole TOML sections."""
    sec = tmp_path / "tok"
    if not sec.exists():
        sec.write_text("00000000-1111-2222-3333-444444444444\n")
        sec.chmod(0o600)
    raw: dict[str, Any] = {
        "target": {"host": "h", "node": "restore01", "token_id": "pbv@pve!t", "token_secret_file": str(sec)},
        "restore": {"backup_storage": "pbs", "target_storage": "local-lvm", "isolated_bridge": "vmbr99"},
        "run": {"log_dir": str(tmp_path / "logs"), "settle_s": 0},
        "vm": [dict(v) for v in vms],
    }
    for name, values in sections.items():
        raw[name] = {**raw.get(name, {}), **values}
    return parse_config(raw, tmp_path / "config.toml")


def add_backup(pve: FakePve, vmid: int, ctime: int = NOW_CTIME, config: dict[str, str] | None = None) -> BackupRef:
    ref = BackupRef(volid=f"pbs:backup/vm/{vmid}/{ctime}", vmid=vmid, ctime=ctime, size=10 * 2**30)
    pve.add_backup(ref, config)
    return ref


class FakeClock:
    """Monotonic clock advanced only by :meth:`sleep`."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


class ApiGuest:
    """Minimal GuestAgent over FakePve (the real one lives in pbv.pve, which we must not import)."""

    def __init__(self, api: FakePve, vmid: int) -> None:
        self.api = api
        self.vmid = vmid

    def ping(self) -> bool:
        return self.api.agent_ping(self.vmid)

    def exec(self, argv: Sequence[str], *, timeout_s: float, input_data: bytes | None = None) -> ExecResult:
        pid = self.api.agent_exec(self.vmid, argv, input_data)
        st = self.api.agent_exec_status(self.vmid, pid)
        return ExecResult(st.exitcode, st.stdout, st.stderr, 0.0)

    def write_file(self, path: str, content: bytes) -> None:
        self.api.agent_file_write(self.vmid, path, content)

    def os_family(self) -> OsFamily:
        osid = self.api.agent_osinfo(self.vmid).get("id", "")
        return OsFamily.WINDOWS if osid == "mswindows" else (OsFamily.LINUX if osid else OsFamily.UNKNOWN)

    def ip_addresses(self) -> list[str]:
        out = []
        for iface in self.api.agent_network_interfaces(self.vmid):
            for a in iface.get("ip-addresses", []):
                if not a["ip-address"].startswith("127."):
                    out.append(a["ip-address"])
        return out


@dataclasses.dataclass
class Env:
    tmp_path: Path
    pve: FakePve
    checks: FakeCheckSuite
    console: FakeConsole
    notifier: RecordingNotifier
    clock: FakeClock
    node_shell: FakeNodeShell

    def runner(self, cfg: Config, *, notifiers: Sequence[Any] | None = None, **kw: Any) -> Runner:
        """Runner over the fakes; ``node_shell`` defaults to the fake one when the config enables it."""
        kw.setdefault("console", self.console)
        if cfg.node_shell.mode != "off":
            kw.setdefault("node_shell", self.node_shell)
        kw.setdefault("run_id", "20261007T020000Z-ab12")
        kw.setdefault("sleep", self.clock.sleep)
        kw.setdefault("clock", self.clock)
        return Runner(
            cfg,
            self.pve,
            self.checks,
            [self.notifier] if notifiers is None else notifiers,
            guest_factory=lambda vmid: ApiGuest(self.pve, vmid),
            **kw,
        )

    def cfg(self, **kw: Any) -> Config:
        return make_cfg(self.tmp_path, **kw)


@pytest.fixture
def env(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> Env:
    caplog.set_level(logging.DEBUG, logger="pbv")
    pve = FakePve(node="restore01")
    return Env(tmp_path, pve, FakeCheckSuite(), FakeConsole(), RecordingNotifier(), FakeClock(), node_shell(pve))


def node_shell(pve: FakePve | None = None, host: str = "restore01", **kw: Any) -> FakeNodeShell:
    """FakeNodeShell whose ``kernel.hostname`` matches the configured node (preflight checks it)."""
    shell = FakeNodeShell(pve, **kw)
    shell.sysctls["kernel.hostname"] = host
    return shell


def names(calls: list[tuple[str, tuple[Any, ...]]]) -> list[str]:
    return [c[0] for c in calls]


def find_calls(pve: FakePve, name: str) -> list[tuple[Any, ...]]:
    return [args for n, args in pve.calls if n == name]
