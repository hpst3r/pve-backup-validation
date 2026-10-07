"""Shared helpers for the adversarial review tests (gated by ``PBV_REVIEW=1``)."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from pbv.config import Config, parse_config
from pbv.core import BackupRef, ExecResult, OsFamily
from pbv.orchestrator import Runner
from pbv.testing.fakes import FakeCheckSuite, FakePve, RecordingNotifier

REVIEW = os.environ.get("PBV_REVIEW") == "1"
NOW_CTIME = 1_790_000_000
TEMP = 900_105


def review_bug(reason: str) -> None:
    """Skip unless PBV_REVIEW=1, so the default suite stays green."""
    if not REVIEW:
        pytest.skip("BUG: " + reason)


def raw_config(tmp_path: Path, **sections: Any) -> dict[str, Any]:
    sec = tmp_path / "tok"
    if not sec.exists():
        sec.write_text("00000000-1111-2222-3333-444444444444\n")
        sec.chmod(0o600)
    raw: dict[str, Any] = {
        "target": {"host": "h", "node": "restore01", "token_id": "pbv@pve!t", "token_secret_file": str(sec)},
        "restore": {"backup_storage": "pbs", "target_storage": "local-lvm", "isolated_bridge": "vmbr99"},
        "run": {"log_dir": str(tmp_path / "logs"), "settle_s": 0, "lock_file": str(tmp_path / "pbv.lock")},
        "notify": {"json": {"dir": str(tmp_path / "reports")}},
        "vm": [{"vmid": 105}],
    }
    for name, values in sections.items():
        raw[name] = values if isinstance(values, list) else {**raw.get(name, {}), **values}
    return raw


def make_cfg(tmp_path: Path, **sections: Any) -> Config:
    return parse_config(raw_config(tmp_path, **sections), tmp_path / "config.toml")


def add_backup(pve: FakePve, vmid: int = 105, config: dict[str, str] | None = None) -> BackupRef:
    ref = BackupRef(volid=f"pbs:backup/vm/{vmid}/{NOW_CTIME}", vmid=vmid, ctime=NOW_CTIME, size=10 * 2**30)
    pve.add_backup(ref, config)
    return ref


class FakeClock:
    """Monotonic clock advanced only by :meth:`sleep`."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


class ApiGuest:
    """Minimal GuestAgent over FakePve (pbv.pve is not imported by orchestrator tests)."""

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
        return OsFamily.LINUX

    def ip_addresses(self) -> list[str]:
        return []


def make_runner(
    cfg: Config,
    pve: FakePve,
    *,
    checks: Any = None,
    notifiers: Sequence[Any] | None = None,
    should_stop: Callable[[], bool] = lambda: False,
    **kw: Any,
) -> Runner:
    clock = FakeClock()
    kw.setdefault("console", None)  # the screenshot path is known-broken until SPEC §1a lands
    return Runner(
        cfg,
        pve,
        checks if checks is not None else FakeCheckSuite(),
        [RecordingNotifier()] if notifiers is None else notifiers,
        guest_factory=lambda vmid: ApiGuest(pve, vmid),
        run_id="20261007T020000Z-ab12",
        should_stop=should_stop,
        sleep=clock.sleep,
        clock=clock,
        **kw,
    )
