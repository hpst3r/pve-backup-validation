"""CLI wiring and command tests (architect-owned), using FakePve injected via build_api."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pbv import cli
from pbv.core import BackupRef
from pbv.testing.fakes import FakePve, GuestProfile


def write_config(tmp_path: Path, extra: str = "", vms: str = "[[vm]]\nvmid = 105\n") -> Path:
    sec = tmp_path / "tok"
    sec.write_text("00000000-1111-2222-3333-444444444444\n")
    sec.chmod(0o600)
    p = tmp_path / "config.toml"
    p.write_text(
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
{extra}
{vms}
""",
        encoding="utf-8",
    )
    return p


@pytest.fixture
def pve(monkeypatch: pytest.MonkeyPatch) -> FakePve:
    fake = FakePve()
    fake.add_backup(
        BackupRef(volid="pbs:backup/vm/105/2026-10-06T02:00:00Z", vmid=105, ctime=1_791_252_000, size=2**30),
        {"name": "web01", "memory": "2048", "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0", "agent": "1"},
    )
    fake.guest_profile[105] = GuestProfile(boot_polls=0)
    monkeypatch.setattr(cli, "build_api", lambda cfg: fake)
    return fake


def test_config_error_exit_2(tmp_path, capsys):
    assert cli.main(["-c", str(tmp_path / "missing.toml"), "check-config"]) == 2
    assert "config error" in capsys.readouterr().err


def test_check_config(tmp_path, capsys):
    assert cli.main(["-c", str(write_config(tmp_path)), "check-config"]) == 0
    out = capsys.readouterr().out
    assert "config OK" in out and "node_shell=off" in out


def test_default_command_is_run(tmp_path, pve):
    assert cli.main(["-c", str(write_config(tmp_path))]) == 0
    assert any(c[0] == "restore_vm" for c in pve.calls)


def test_run_happy_path_writes_json_and_cleans_up(tmp_path, pve, capsys):
    rc = cli.main(["-c", str(write_config(tmp_path)), "run", "--vmid", "105"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert 900105 not in pve.vms
    latest = json.loads((tmp_path / "reports" / "latest.json").read_text())
    assert latest["status"] == "pass" and latest["vms"][0]["temp_vmid"] == 900105
    assert latest["vms"][0]["cleanup_ok"] is True
    # Everything went through the restore node's API only, with the isolated bridge applied before start.
    set_calls = [c for c in pve.calls if c[0] == "update_vm_config"]
    assert any("bridge=vmbr99" in str(c) for c in set_calls)
    starts = [i for i, c in enumerate(pve.calls) if c[0] == "start_vm"]
    sanit = [i for i, c in enumerate(pve.calls) if c[0] == "update_vm_config" and "bridge=vmbr99" in str(c)]
    assert sanit and starts and sanit[-1] < starts[0]


def test_run_no_backup_exit_1(tmp_path, pve, capsys):
    assert cli.main(["-c", str(write_config(tmp_path)), "run", "--vmid", "222"]) == 1
    assert "NO_BACKUP" in capsys.readouterr().out


def test_dry_run_creates_nothing(tmp_path, pve, capsys):
    assert cli.main(["-c", str(write_config(tmp_path)), "run", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "900105" in out and "nothing was created" in out
    assert not [c for c in pve.calls if c[0] in ("restore_vm", "update_vm_config", "destroy_vm", "start_vm")]


def test_preflight_clustered_node_exit_2(tmp_path, pve, capsys):
    pve.cluster = [{"type": "cluster", "name": "prod", "nodes": 3}, {"type": "node", "name": "restore01", "local": 1}]
    assert cli.main(["-c", str(write_config(tmp_path)), "preflight"]) == 2
    assert cli.main(["-c", str(write_config(tmp_path)), "run"]) == 2
    assert not any(c[0] == "restore_vm" for c in pve.calls)


def test_preflight_ok(tmp_path, pve, capsys):
    assert cli.main(["-c", str(write_config(tmp_path)), "preflight"]) == 0
    assert "standalone" in capsys.readouterr().out


def test_lock_held_exit_4(tmp_path, pve):
    from pbv.orchestrator import RunLock

    cfgp = write_config(tmp_path)
    with RunLock(tmp_path / "pbv.lock"):
        assert cli.main(["-c", str(cfgp), "run"]) == 4
    assert not any(c[0] == "restore_vm" for c in pve.calls)


def test_list_backups(tmp_path, pve, capsys):
    assert cli.main(["-c", str(write_config(tmp_path)), "list-backups", "--vmid", "105", "--vmid", "333"]) == 0
    out = capsys.readouterr().out
    assert "pbs:backup/vm/105/" in out and "333  NO BACKUP" in out


def test_cleanup_requires_yes_noninteractive(tmp_path, pve, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["-c", str(write_config(tmp_path)), "cleanup"]) == 2


def test_cleanup_sweeps_tagged_skips_kept(tmp_path, pve, capsys):
    pve.add_vm(900105, {"name": "x", "tags": "pbv-temp"}, status="running")
    pve.add_vm(900106, {"name": "y", "tags": "pbv-temp;pbv-keep"})
    assert cli.main(["-c", str(write_config(tmp_path)), "cleanup", "--yes"]) == 0
    out = capsys.readouterr().out
    assert 900105 not in pve.vms and 900106 in pve.vms and "kept (use --include-kept): 900106" in out
    assert cli.main(["-c", str(write_config(tmp_path)), "cleanup", "--yes", "--include-kept"]) == 0
    assert 900106 not in pve.vms


def test_cleanup_refuses_when_untagged_vm_in_temp_range(tmp_path, pve, capsys):
    pve.add_vm(900107, {"name": "not-ours"})
    assert cli.main(["-c", str(write_config(tmp_path)), "cleanup", "--yes"]) == 2
    assert 900107 in pve.vms and not any(c[0] == "destroy_vm" for c in pve.calls)


def test_notify_test_json_only(tmp_path, capsys):
    assert cli.main(["-c", str(write_config(tmp_path)), "notify-test"]) == 0
    assert json.loads(capsys.readouterr().out) == {"json": "ok"}


def test_no_notify_disables_remote_notifiers(tmp_path, pve):
    extra = '[notify.ntfy]\nenabled = true\nwhen = "always"\ntopic = "pbv-test-topic"\nserver = "http://127.0.0.1:9"\n'
    rc = cli.main(["-c", str(write_config(tmp_path, extra=extra)), "run", "--no-notify"])
    assert rc == 0
    latest = json.loads((tmp_path / "reports" / "latest.json").read_text())
    assert latest["notify_errors"] == []
