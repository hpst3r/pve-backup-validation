"""Adversarial review: ``pbv.cli`` wiring against the real package APIs (fake PVE injected)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pbv import cli
from pbv.orchestrator import Runner
from pbv.testing.fakes import FakeCheckSuite, FakePve, GuestProfile

from ._support import ApiGuest, add_backup, review_bug


def _write_config(tmp_path: Path) -> Path:
    sec = tmp_path / "tok"
    sec.write_text("00000000-1111-2222-3333-444444444444\n")
    sec.chmod(0o600)
    path = tmp_path / "config.toml"
    path.write_text(
        f"""
[target]
host = "h"
node = "restore01"
token_id = "pbv@pve!t"
token_secret_file = "{sec}"

[restore]
backup_storage = "pbs"
target_storage = "local-lvm"
isolated_bridge = "vmbr99"

[run]
log_dir = "{tmp_path / "logs"}"
lock_file = "{tmp_path / "pbv.lock"}"
settle_s = 0

[notify.json]
dir = "{tmp_path / "reports"}"

[[vm]]
vmid = 105
""",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def pve(monkeypatch: pytest.MonkeyPatch) -> FakePve:
    fake = FakePve()
    add_backup(fake)
    fake.guest_profile[105] = GuestProfile(boot_polls=0)  # no real 5 s boot-poll sleep
    monkeypatch.setattr(cli, "build_api", lambda cfg: fake)
    return fake


def test_check_config_command_works(tmp_path: Path) -> None:
    review_bug(
        "cli.py:258 cmd_check_config reads cfg.screenshot.mode, which no longer exists (ScreenshotConfig is "
        "enabled+when since SPEC §1a) → AttributeError traceback for `pbv check-config`"
    )
    assert cli.main(["-c", str(_write_config(tmp_path)), "check-config"]) == 0


def test_dry_run_wiring(tmp_path: Path, pve: FakePve, capsys: pytest.CaptureFixture[str]) -> None:
    review_bug(
        "cli.py:100 build_runner calls ConsoleCapture.from_config(api, cfg.screenshot) — wrong signature and "
        "reads screenshot.mode → every `pbv run` / `--dry-run` / `cleanup` dies with AttributeError"
    )
    assert cli.main(["-c", str(_write_config(tmp_path)), "run", "--dry-run"]) == 0
    assert "900105" in capsys.readouterr().out
    assert not [c for c in pve.calls if c[0] in ("restore_vm", "update_vm_config", "destroy_vm")]


def test_full_run_wiring_happy_path(tmp_path: Path, pve: FakePve) -> None:
    review_bug(
        "cli.py:79-112 build_runner: crashes before Runner is built (ConsoleCapture.from_config), never builds "
        "a NodeShellRunner nor passes node_shell= to Runner/preflight (SPEC §1a) — `pbv run` cannot pass"
    )
    rc = cli.main(["-c", str(_write_config(tmp_path)), "run"])
    assert rc == 0
    assert 900105 not in pve.vms
    assert list((tmp_path / "reports").glob("*.json"))


def test_cleanup_exit_code_ignores_intentionally_kept_vms(
    tmp_path: Path, pve: FakePve, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    review_bug(
        "cli.py:245-248 cmd_cleanup without --include-kept counts the pbv-keep VMs it deliberately skipped "
        "(and foreign untagged VMs) as 'still present' and exits 3 (cleanup failure) on every invocation"
    )

    def runner(cfg: Any, api: Any, **kw: Any) -> Runner:  # sidestep the build_runner wiring bug
        return Runner(cfg, api, FakeCheckSuite(), [], guest_factory=lambda v: ApiGuest(api, v), sleep=lambda s: None)

    monkeypatch.setattr(cli, "build_runner", runner)
    pve.add_vm(900_200, {"name": "leftover", "tags": "pbv-temp"})
    pve.add_vm(900_300, {"name": "kept", "tags": "pbv-temp;pbv-keep"})
    rc = cli.main(["-c", str(_write_config(tmp_path)), "cleanup", "--yes"])
    assert 900_200 not in pve.vms and 900_300 in pve.vms
    assert rc == 0, capsys.readouterr().out
