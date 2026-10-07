"""End-to-end: the real object graph (CheckEngine, notifiers, Runner, PveGuestAgent, ConsoleCapture,
NodeShellRunner with a fake ``run``) against FakePve, driven through ``pbv.cli.main``.

Covers the user-visible contract: a passthrough VM gets its devices removed via the root node shell and
boots on the isolated bridge; a guest script is uploaded and executed with the PBV_* environment; a failing
check produces a FAIL report with a screenshot; the temp VM is always gone afterwards; exit codes match SPEC §8.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pbv import cli
from pbv.core import BackupRef, OsFamily
from pbv.testing.fakes import FakePve, GuestProfile


class FakeNodeRun:
    """Stands in for subprocess.run used by NodeShellRunner (local mode): emulates `qm` and `sysctl` as root."""

    def __init__(self, pve: FakePve) -> None:
        self.pve = pve
        self.calls: list[list[str]] = []

    def __call__(self, argv, *a, **kw):
        argv = list(argv)
        self.calls.append(argv)
        out, rc = b"", 0
        if argv[:2] == ["qm", "set"]:
            vmid = int(argv[2])
            vm = self.pve.vms[vmid]
            rest = argv[3:]
            i = 0
            while i < len(rest):
                k, v = rest[i][2:], rest[i + 1]
                if k == "delete":
                    for d in v.split(","):
                        vm.config.pop(d, None)
                else:
                    vm.config[k] = v
                i += 2
        elif argv[:2] == ["qm", "unlock"]:
            self.pve.vms[int(argv[2])].config.pop("lock", None)
        elif argv[:2] == ["qm", "monitor"]:
            cmd = (kw.get("input") or b"").decode()
            path = cmd.split()[1]
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
        elif argv[:2] == ["qm", "list"]:
            out = b"VMID NAME STATUS\n"
        elif argv[:2] == ["sysctl", "-n"]:
            out = {"kernel.hostname": b"restore01\n", "net.ipv6.conf.vmbr99.disable_ipv6": b"1\n"}.get(argv[2], b"")
            rc = 0 if out else 255
        else:
            rc = 127
        return subprocess.CompletedProcess(argv, rc, stdout=out, stderr=b"" if rc == 0 else b"not found\n")


def write_config(tmp_path: Path, vms: str, extra: str = "") -> Path:
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
boot_timeout_s = 30

[node_shell]
mode = "local"
remote_dir = "{tmp_path / "screendump"}"

[screenshot]
enabled = true
when = "failure"

[notify.json]
dir = "{tmp_path / "reports"}"
{extra}
{vms}
""",
        encoding="utf-8",
    )
    return p


@pytest.fixture
def world(tmp_path, monkeypatch):
    pve = FakePve()
    noderun = FakeNodeRun(pve)
    import pbv.pve as pvepkg

    real_from_config = pvepkg.NodeShellRunner.from_config

    def from_config(cfg, *, node, **kw):
        return real_from_config(cfg, node=node, run=noderun, geteuid=lambda: 0, which=lambda n: f"/usr/sbin/{n}", **kw)

    monkeypatch.setattr(pvepkg.NodeShellRunner, "from_config", staticmethod(from_config))
    monkeypatch.setattr(cli, "build_api", lambda cfg: pve)

    # Real PveGuestAgent, but with instant polling so the test doesn't sleep.
    real_build_runner = cli.build_runner

    def build_runner(cfg, api, **kw):
        from pbv.pve import PveGuestAgent

        kw.setdefault("guest_factory", lambda vmid: PveGuestAgent(api, vmid, sleep=lambda s: None))
        runner = real_build_runner(cfg, api, **kw)
        runner.sleep = lambda s: None  # boot poll / backoff
        return runner

    monkeypatch.setattr(cli, "build_runner", build_runner)
    return pve, noderun, tmp_path


def backup(pve: FakePve, vmid: int, cfg: dict[str, str]) -> None:
    pve.add_backup(
        BackupRef(volid=f"pbs:backup/vm/{vmid}/2026-10-06T02:00:00Z", vmid=vmid, ctime=1_791_252_000, size=2**30), cfg
    )


def latest(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "reports" / "latest.json").read_text())


def test_passthrough_vm_sanitized_via_root_shell_and_script_runs(world):
    pve, noderun, tmp = world  # noqa: RUF059
    backup(
        pve,
        105,
        {
            "name": "gpu01",
            "memory": "4096",
            "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20,firewall=1",
            "hostpci0": "host=0000:01:00.0,pcie=1",
            "usb0": "host=1234:5678",
            "ide2": "isostore:iso/debian.iso,media=cdrom",
            "agent": "0",
        },
    )
    script = tmp / "check.sh"
    script.write_text("#!/bin/sh\necho hello\n")
    seen_env: dict[str, str] = {}

    def on_exec(argv, data):
        if argv[:1] == ["/usr/bin/env"]:
            seen_env.update(a.split("=", 1) for a in argv[1:] if "=" in a and not a.startswith("/"))
            return 0, "hello\n", ""
        return 0, "", ""

    pve.guest_profile[105] = GuestProfile(os=OsFamily.LINUX, boot_polls=1, on_exec=on_exec)
    vms = f'[[vm]]\nvmid = 105\nmode = "manual"\n  [[vm.check]]\n  type = "script"\n  path = "{script}"\n  env = {{ APP = "x" }}\n'
    rc = cli.main(["-c", str(write_config(tmp, vms)), "run"])
    rep = latest(tmp)
    assert rc == 0, json.dumps(rep, indent=1)[:3000]
    vm = rep["vms"][0]
    assert vm["status"] == "pass" and vm["cleanup_ok"]
    # Root-only keys went through `qm set`, the rest through the API.
    qm_sets = [c for c in noderun.calls if c[:2] == ["qm", "set"]]
    assert qm_sets and "hostpci0" in " ".join(qm_sets[0]) and "usb0" in " ".join(qm_sets[0])
    api_updates = [c for c in pve.calls if c[0] == "update_vm_config"]
    assert any("bridge=vmbr99" in str(c) and "tag=20" not in str(c) for c in api_updates)
    # Script uploaded and run with the PBV_* environment.
    assert seen_env["PBV_VMID"] == "105" and seen_env["PBV_TEMP_VMID"] == "900105" and seen_env["APP"] == "x"
    assert seen_env["PBV_TARGET_NODE"] == "restore01"
    assert 900105 not in pve.vms


def test_failing_check_reports_fail_with_screenshot_and_cleans_up(world):
    pve, noderun, tmp = world  # noqa: RUF059
    backup(pve, 106, {"name": "web02", "memory": "1024", "net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0", "agent": "1"})
    pve.guest_profile[106] = GuestProfile(boot_polls=0, on_exec=lambda argv, d: (3, "inactive\n", ""))
    vms = '[[vm]]\nvmid = 106\nmode = "manual"\n  [[vm.check]]\n  type = "systemd"\n  unit = "nginx"\n'
    rc = cli.main(["-c", str(write_config(tmp, vms)), "run"])
    rep = latest(tmp)
    assert rc == 1
    vm = rep["vms"][0]
    assert vm["status"] == "fail" and vm["failure_code"] == "CHECKS_FAILED"
    assert vm["screenshots"] and Path(vm["screenshots"][0]).read_bytes().startswith(b"\x89PNG")
    assert vm["cleanup_ok"] and 900106 not in pve.vms


def test_needs_root_without_node_shell(world):
    pve, noderun, tmp = world  # noqa: RUF059
    backup(
        pve, 107, {"name": "gpu02", "hostpci0": "host=0000:02:00.0", "net0": "virtio=BC:24:11:00:00:03,bridge=vmbr0"}
    )
    cfgp = write_config(tmp, "[[vm]]\nvmid = 107\n")
    text = cfgp.read_text().replace('mode = "local"', 'mode = "off"').replace("enabled = true", "enabled = false")
    cfgp.write_text(text)
    rc = cli.main(["-c", str(cfgp), "run"])
    vm = latest(tmp)["vms"][0]
    assert rc == 1 and vm["failure_code"] == "SANITIZE_NEEDS_ROOT" and vm["cleanup_ok"]
    assert 900107 not in pve.vms and not any(c[0] == "start_vm" for c in pve.calls)


def test_destroy_failure_exit_3_and_manual_cleanup_line(world, capsys):
    pve, noderun, tmp = world  # noqa: RUF059
    backup(pve, 108, {"name": "db01", "net0": "virtio=BC:24:11:00:00:04,bridge=vmbr0", "agent": "1"})
    pve.guest_profile[108] = GuestProfile(boot_polls=0)
    pve.destroy_fails.add(900108)
    rc = cli.main(["-c", str(write_config(tmp, "[[vm]]\nvmid = 108\n")), "run"])
    assert rc == 3
    assert "MANUAL CLEANUP REQUIRED: VM 900108" in capsys.readouterr().out
    assert latest(tmp)["vms"][0]["cleanup_ok"] is False


def test_restore_failure_with_locked_leftover_is_unlocked_and_destroyed(world):
    pve, noderun, tmp = world  # noqa: RUF059
    backup(pve, 109, {"name": "x", "net0": "virtio=BC:24:11:00:00:05,bridge=vmbr0"})
    pve.restore_fails[109] = "unable to restore: chunk missing"
    rc = cli.main(["-c", str(write_config(tmp, "[[vm]]\nvmid = 109\n")), "run"])
    vm = latest(tmp)["vms"][0]
    assert rc == 1 and vm["failure_code"] == "RESTORE_FAIL" and vm["cleanup_ok"]
    assert ["qm", "unlock", "900109"] in noderun.calls
    assert 900109 not in pve.vms
