"""Adversarial review: orchestrator lifecycle, cleanup guarantees, signals, preflight isolation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pbv.core import ApiError, CheckResult, CheckSpec, Status
from pbv.orchestrator import PreflightFailure, exit_code, preflight
from pbv.testing.fakes import FakeCheckSuite, FakePve

from ._support import TEMP, add_backup, make_cfg, make_runner, review_bug

ONE_CHECK = {"vmid": 105, "mode": "manual", "check": [{"type": "command", "argv": ["true"]}]}


class _RaisingChecks(FakeCheckSuite):
    """A check suite whose run() raises a BaseException (not an Exception)."""

    def __init__(self, exc: BaseException) -> None:
        super().__init__(planned=[CheckSpec(type="command", name="c1", params={"argv": ["true"]})])
        self.exc = exc

    def run(self, spec: CheckSpec, guest: Any, ctx: Any) -> CheckResult:
        raise self.exc


def test_cleanup_runs_when_lifecycle_raises_base_exception(tmp_path: Path) -> None:
    review_bug(
        "runner.py:462-477 cleanup is not in a finally: a BaseException (KeyboardInterrupt/SystemExit) or any "
        "exception from _screenshot skips _cleanup_vm and leaves the temp VM behind, unreported"
    )
    pve = FakePve()
    add_backup(pve)
    runner = make_runner(make_cfg(tmp_path), pve, checks=_RaisingChecks(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        runner.run()
    assert TEMP not in pve.vms, "temp VM left behind after KeyboardInterrupt escaped the lifecycle"


def test_cleanup_runs_when_screenshot_step_raises(tmp_path: Path) -> None:
    review_bug(
        "runner.py:475-477 _screenshot runs outside the try; an exception there (today: AttributeError on "
        "cfg.screenshot.mode for every started VM when a console is wired) skips cleanup and the whole report"
    )
    pve = FakePve()
    add_backup(pve)
    runner = make_runner(make_cfg(tmp_path), pve)

    def boom(st: Any) -> None:
        raise RuntimeError("screenshot bug")

    runner._screenshot = boom  # type: ignore[method-assign]
    try:
        report = runner.run()
    except RuntimeError:
        report = None
    assert TEMP not in pve.vms, "temp VM left behind after an exception in the screenshot step"
    assert report is not None, "run() raised instead of returning a report (no JSON report / notification)"


def test_interrupt_during_last_check_marks_report_interrupted(tmp_path: Path) -> None:
    review_bug(
        "runner.py:778-786/_run_vms: a stop flag set during the LAST check of the LAST VM is never observed: "
        "report.interrupted stays False, status PASS, exit 0 instead of 130"
    )
    stop = {"flag": False}

    class StopChecks(FakeCheckSuite):
        def run(self, spec: CheckSpec, guest: Any, ctx: Any) -> CheckResult:
            stop["flag"] = True  # SIGTERM arrives while the check is running
            return super().run(spec, guest, ctx)

    pve = FakePve()
    add_backup(pve)
    cfg = make_cfg(tmp_path, vm=[ONE_CHECK])  # type: ignore[arg-type]
    report = make_runner(cfg, pve, checks=StopChecks(), should_stop=lambda: stop["flag"]).run()
    assert report.interrupted
    assert exit_code(report) == 130


def test_signal_during_final_cleanup_is_reported(tmp_path: Path) -> None:
    review_bug(
        "runner.py:417-441: a SIGTERM recorded while the last VM's cleanup runs is dropped; the run "
        "reports PASS / exit 0 although SPEC §4 says the report is marked interrupted (exit 130)"
    )
    stop = {"flag": False}

    class SignalOnDestroy(FakePve):
        def destroy_vm(self, vmid: int, *, skiplock: bool = False) -> str:
            stop["flag"] = True
            return super().destroy_vm(vmid, skiplock=skiplock)

    pve = SignalOnDestroy()
    add_backup(pve)
    report = make_runner(make_cfg(tmp_path), pve, should_stop=lambda: stop["flag"]).run()
    assert TEMP not in pve.vms  # cleanup finished (good)
    assert report.interrupted and exit_code(report) == 130


def test_sweep_failure_is_reported(tmp_path: Path) -> None:
    review_bug(
        "runner.py:348-352: a tagged leftover that the startup sweep cannot destroy is only logged; "
        "report.sweep_failures stays empty, the run is PASS and exit 0 (in-flight per briefs/orchns.md #4)"
    )
    pve = FakePve()
    add_backup(pve)
    pve.add_vm(900_200, {"name": "leftover", "tags": "pbv-temp"})
    pve.destroy_fails.add(900_200)
    report = make_runner(make_cfg(tmp_path), pve).run()
    assert 900_200 in pve.vms
    assert report.sweep_failures, "leftover temp VM still exists but is not reported anywhere"
    assert exit_code(report) == 3


def test_restore_post_5xx_after_send_still_cleans_up(tmp_path: Path) -> None:
    review_bug(
        "runner.py:638-643: a restore POST that fails with an HTTP status after it was sent (pveproxy "
        "500 'got timeout' / 502-504, ApiError.transient) may still have created the VM, but temp is only "
        "added to created_by_run for status None; cleanup is SKIPPED and the untagged VM blocks every later "
        "preflight (temp_range guard)"
    )

    class SlowProxy(FakePve):
        def restore_vm(self, vmid: int, archive: str, storage: str, **kw: Any) -> str:
            super().restore_vm(vmid, archive, storage, **kw)  # pvedaemon forked the worker...
            raise ApiError("POST /nodes/restore01/qemu: HTTP 500: got timeout", status=500, transient=True)

    pve = SlowProxy()
    add_backup(pve)
    report = make_runner(make_cfg(tmp_path), pve).run()
    vm = report.vms[0]
    assert vm.failure_code == "RESTORE_FAIL"
    assert TEMP not in pve.vms or not vm.cleanup_ok, "VM may exist but cleanup was skipped and cleanup_ok=True"


def test_keep_on_failure_never_keeps_unsanitized_vm_on_production_bridge(tmp_path: Path) -> None:
    review_bug(
        "runner.py:837-847: keep_on_failure keeps a VM whose sanitize FAILED, so it is left with its NIC on "
        "the production bridge (and passthrough devices); a manual start puts a clone of a production VM "
        "(same IPs) on the production network"
    )
    pve = FakePve()  # token_is_root=False: the API refuses to delete hostpci0 → sanitize fails
    add_backup(
        pve,
        config={
            "name": "db",
            "memory": "2048",
            "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0",
            "hostpci0": "host=0000:01:00.0",
        },
    )
    cfg = make_cfg(tmp_path, restore={"keep_on_failure": True})
    report = make_runner(cfg, pve).run()
    assert report.vms[0].status.rank >= Status.FAIL.rank
    if TEMP in pve.vms:
        assert "vmbr0" not in pve.vms[TEMP].config.get("net0", ""), "kept VM still on production bridge vmbr0"


@pytest.mark.parametrize(
    "extra",
    [{"method": "dhcp"}, {"method6": "auto"}, {"method6": "dhcp"}],
    ids=["dhcp4", "slaac6", "dhcp6"],
)
def test_preflight_rejects_bridge_that_obtains_an_address(tmp_path: Path, extra: dict[str, str]) -> None:
    review_bug(
        "preflight.py:89-95: the isolation guard only checks static cidr/address/gateway fields; a bridge "
        "with method=dhcp or method6=auto/dhcp gets an address at runtime, so restored guests can reach the "
        "restore node (8006/ssh) — SPEC §1 'the bridge cannot route anywhere'"
    )
    pve = FakePve()
    pve.networks = [{"iface": "vmbr99", "type": "bridge", "bridge_ports": "", "active": 1, **extra}]
    with pytest.raises(PreflightFailure):
        preflight(pve, make_cfg(tmp_path))
