"""Runner lifecycle, cleanup, sweep, interrupts and reporting (A2–A7, A9–A11)."""

from __future__ import annotations

import logging
import os
import signal
import time
from pathlib import Path
from typing import Any

import pytest

from pbv.core import (
    ApiError,
    BackupRef,
    CheckSpec,
    PbvError,
    RunReport,
    SafetyError,
    Status,
    StepResult,
    VmResult,
)
from pbv.orchestrator import Runner, StopFlag, exit_code
from pbv.testing.fakes import FakeCheckSuite, FakeNodeShell, FakePve, GuestProfile, RecordingNotifier

from .conftest import NOW_CTIME, Env, add_backup, find_calls, names

C1 = CheckSpec(type="command", name="c1", params={"argv": ["true"]})
C2 = CheckSpec(type="command", name="c2", params={"argv": ["true"]})
NODE_SHELL: dict[str, Any] = {"node_shell": {"mode": "local"}}
SHOTS: dict[str, Any] = {"screenshot": {"enabled": True}, **NODE_SHELL}
SHOTS_ALWAYS: dict[str, Any] = {"screenshot": {"enabled": True, "when": "always"}, **NODE_SHELL}


def step(vm: VmResult, name: str) -> StepResult:
    matches = [s for s in vm.steps if s.name == name]
    assert matches, f"no step {name} in {[s.name for s in vm.steps]}"
    return matches[-1]


def two_vms(env: Env, **kw: Any):
    add_backup(env.pve, 105)
    add_backup(env.pve, 110)
    return env.cfg(vms=[{"vmid": 105}, {"vmid": 110}], **kw)


# ── A2 happy path ───────────────────────────────────────────────────────────────
def test_happy_path(env: Env):
    old = add_backup(env.pve, 105, ctime=NOW_CTIME - 86400)
    new = add_backup(
        env.pve,
        105,
        ctime=NOW_CTIME,
        config={"name": "web01", "net0": "virtio=AA:BB:CC:00:00:01,bridge=vmbr0,tag=5", "protection": "1"},
    )
    add_backup(env.pve, 105, ctime=NOW_CTIME - 3600)
    env.checks.planned = [C1, C2]
    cfg = env.cfg()
    report = env.runner(cfg, tool_version="1.2.3").run()

    assert report.status is Status.PASS and exit_code(report) == 0
    assert report.tool_version == "1.2.3" and report.run_id == "20261007T020000Z-ab12"
    vm = report.vms[0]
    assert vm.status is Status.PASS and vm.failure_code == "" and vm.cleanup_ok
    assert vm.backup == new and vm.backup != old
    assert vm.name == "web01" and vm.os == "linux" and vm.guest_ips == ["10.99.0.5"]
    assert [s.name for s in vm.steps] == [
        "resolve_backup",
        "temp_vmid",
        "space",
        "restore",
        "mark",
        "sanitize",
        "start",
        "boot",
        "settle",
        "checks",
        "cleanup",
    ]
    assert all(s.status in (Status.PASS, Status.SKIPPED) for s in vm.steps)
    assert find_calls(env.pve, "restore_vm") == [(900105, new.volid, "local-lvm", True, None, None)]
    order = names(env.pve.calls)
    updates = [i for i, n in enumerate(order) if n == "update_vm_config"]
    assert len(updates) == 2 and updates[-1] < order.index("start_vm")
    mark, sanitize = find_calls(env.pve, "update_vm_config")
    assert mark[0] == 900105
    assert mark[1] == {
        "tags": "pbv-temp",
        "description": "pbv temporary restore test of VM 105 (web01) — run 20261007T020000Z-ab12 — safe to delete",
        "onboot": "0",
    }
    assert mark[2] == ("protection",)
    assert "bridge=vmbr99" in sanitize[1]["net0"] and "tag=5" not in sanitize[1]["net0"]
    assert any(n.startswith("net0:") for n in vm.sanitized)
    assert env.checks.ran == [("c1", 900105), ("c2", 900105)]
    assert [c.name for c in vm.checks] == ["c1", "c2"]
    assert 900105 not in env.pve.vms
    assert env.console.captured == []  # screenshots off by default
    assert len(env.notifier.vm_results) == 1 and env.notifier.reports == [report]
    assert report.finished_at and report.preflight and report.notify_errors == []


def test_restore_options_pool_and_bwlimit(env: Env):
    add_backup(env.pve, 105)
    report = env.runner(env.cfg(restore={"pool": "pbv", "bwlimit_kib": 50000})).run()
    assert report.status is Status.PASS
    assert find_calls(env.pve, "restore_vm")[0][4:] == ("pbv", 50000)


def test_existing_tags_merged_without_duplicates(env: Env):
    add_backup(env.pve, 105, config={"name": "x", "tags": "prod;pbv-temp,web"})
    env.runner(env.cfg()).run()
    assert find_calls(env.pve, "update_vm_config")[0][1]["tags"] == "prod;pbv-temp;web"


# ── A3 destroy guard ────────────────────────────────────────────────────────────
def test_may_destroy_guard(env: Env):
    cfg = env.cfg()
    r = env.runner(cfg)
    env.pve.add_vm(105, {"name": "prod", "tags": "pbv-temp"})
    env.pve.add_vm(900200, {"name": "foreign"})
    env.pve.add_vm(900300, {"name": "tagged", "tags": "a;pbv-temp"})
    assert not r.may_destroy(105)  # outside the temp range even though tagged
    assert not r.may_destroy(900050)  # below base+100
    assert not r.may_destroy(900200)  # untagged
    assert r.may_destroy(900300)
    r.created_by_run.add(900200)
    assert r.may_destroy(900200)  # this run created it
    r.created_by_run.clear()
    with pytest.raises(SafetyError):
        r._destroy(900200)
    with pytest.raises(SafetyError):
        r._destroy(105)
    assert 105 in env.pve.vms and 900200 in env.pve.vms
    assert not find_calls(env.pve, "destroy_vm") and not find_calls(env.pve, "stop_vm")


def test_guard_refusal_in_cleanup_is_reported_never_destroyed(env: Env):
    class NoGuard(Runner):
        def may_destroy(self, vmid: int) -> bool:
            return False

    add_backup(env.pve, 105)
    r = NoGuard(env.cfg(), env.pve, env.checks, [env.notifier], guest_factory=lambda v: None, sleep=env.clock.sleep)
    report = r.run()
    vm = report.vms[0]
    cl = step(vm, "cleanup")
    assert cl.status is Status.ERROR and cl.error_code == "SAFETY_REFUSED"
    assert vm.status is Status.ERROR and vm.cleanup_ok  # not ours: no MANUAL CLEANUP demand
    assert not find_calls(env.pve, "destroy_vm") and 900105 in env.pve.vms


# ── A4 restore failure ──────────────────────────────────────────────────────────
def test_restore_failure_cleans_locked_vm_and_continues(env: Env):
    cfg = two_vms(env)
    env.pve.restore_fails[105] = "unable to restore: chunk missing"
    report = env.runner(cfg, node_shell=env.node_shell).run()
    vm105, vm110 = report.vms
    assert vm105.status is Status.FAIL and vm105.failure_code == "RESTORE_FAIL"
    assert "chunk missing" in vm105.failure_message and "qmrestore" in vm105.failure_message  # log tail
    assert step(vm105, "cleanup").status is Status.PASS and vm105.cleanup_ok
    assert env.node_shell.unlocks == [900105]  # `qm unlock` for the locked VM, never skiplock
    assert all(not a[1] for n, a in env.pve.calls if n in ("stop_vm", "destroy_vm"))
    assert "start_vm" not in [n for n, a in env.pve.calls if a and a[0] == 900105]
    assert vm110.status is Status.PASS
    assert not env.pve.vms
    assert exit_code(report) == 1


def test_restore_api_error_without_status_cleans_possibly_created_vm(env: Env):
    class FlakyRestore(FakePve):
        def restore_vm(self, vmid, archive, storage, **kw):
            super().restore_vm(vmid, archive, storage, **kw)
            raise ApiError("connection reset", status=None)

    env.pve = FlakyRestore()
    add_backup(env.pve, 105)
    report = env.runner(env.cfg()).run()
    vm = report.vms[0]
    assert vm.failure_code == "RESTORE_FAIL" and vm.status is Status.ERROR
    assert step(vm, "cleanup").status is Status.PASS and 900105 not in env.pve.vms


def test_restore_api_error_4xx_does_not_touch_vm(env: Env):
    add_backup(env.pve, 105)
    env.pve.fail_next["restore_vm"] = ApiError("permission denied", status=403)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "RESTORE_FAIL" and vm.status is Status.FAIL
    assert step(vm, "cleanup").status is Status.SKIPPED
    assert not find_calls(env.pve, "destroy_vm")


@pytest.mark.parametrize("status", [500, 502, 504])
def test_restore_api_error_after_send_cleans_up_created_vm(env: Env, status: int):
    class ProxyTimeout(FakePve):
        def restore_vm(self, vmid, archive, storage, **kw):
            super().restore_vm(vmid, archive, storage, **kw)  # the worker was forked...
            raise ApiError("HTTP error: got timeout", status=status, transient=True)

    env.pve = ProxyTimeout()
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "RESTORE_FAIL" and vm.status is Status.FAIL
    assert step(vm, "cleanup").status is Status.PASS and vm.cleanup_ok
    assert 900105 not in env.pve.vms


def test_restore_api_error_after_send_without_vm_is_clean(env: Env):
    add_backup(env.pve, 105)
    env.pve.fail_next["restore_vm"] = ApiError("HTTP 503", status=503, transient=True)
    vm = env.runner(env.cfg()).run().vms[0]
    cleanup = step(vm, "cleanup")
    assert cleanup.status is Status.PASS and "does not exist" in cleanup.message and vm.cleanup_ok
    assert not find_calls(env.pve, "destroy_vm")


@pytest.mark.parametrize("status", [500, 502])
def test_restore_already_exists_never_destroys_foreign_vm(env: Env, status: int):
    """A foreign VM appears on the temp VMID after the temp_vmid check (race); restore then fails."""

    class Race(FakePve):
        def restore_vm(self, vmid, archive, storage, **kw):
            self.add_vm(vmid, {"name": "foreign"}, status="running")  # untagged, not ours
            try:
                super().restore_vm(vmid, archive, storage, **kw)
            except ApiError as exc:
                raise ApiError(str(exc), status=status) from exc
            raise AssertionError("restore over an existing VM must fail")

    env.pve = Race()
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "RESTORE_FAIL" and "already exists" in vm.failure_message
    assert step(vm, "cleanup").status is Status.SKIPPED
    assert env.pve.vms[900105].config == {"name": "foreign"} and env.pve.vms[900105].status == "running"
    assert not [a for n, a in env.pve.calls if n in ("stop_vm", "destroy_vm", "update_vm_config")]


def test_untagged_temp_vmid_never_destroyed_even_if_restore_raises(env: Env):
    add_backup(env.pve, 105)
    env.pve.add_vm(900105, {"name": "foreign"})
    env.pve.fail_next["restore_vm"] = ApiError("got timeout", status=500, transient=True)
    report = env.runner(env.cfg(run={"sweep_leftovers": False})).run()
    assert report.preflight[-1].name == "temp_range" and exit_code(report) == 2  # refused before any VM
    r = env.runner(env.cfg())
    vm = r._process_vm(r.cfg.vm_target(105)).result  # bypass preflight: the temp_vmid step must refuse too
    assert vm.failure_code == "TEMP_VMID_BUSY" and step(vm, "cleanup").status is Status.SKIPPED
    assert not find_calls(env.pve, "restore_vm") and 900105 in env.pve.vms
    assert not find_calls(env.pve, "destroy_vm")


# ── A5 restore timeout ──────────────────────────────────────────────────────────
def test_restore_timeout_stops_task_and_cleans_up(env: Env):
    add_backup(env.pve, 105)
    env.pve.restore_hangs.add(105)
    report = env.runner(env.cfg(restore={"restore_timeout_s": 60}), node_shell=env.node_shell).run()
    vm = report.vms[0]
    assert vm.failure_code == "RESTORE_TIMEOUT" and vm.status is Status.FAIL
    assert env.node_shell.unlocks == [900105]
    upid = find_calls(env.pve, "wait_task")[0][0]
    assert env.pve.stopped_tasks == [upid]
    assert sum(a[1] for a in find_calls(env.pve, "wait_task") if a[0] == upid) == pytest.approx(60)
    assert step(vm, "cleanup").status is Status.PASS and 900105 not in env.pve.vms


def test_stop_task_error_is_ignored(env: Env):
    add_backup(env.pve, 105)
    env.pve.restore_hangs.add(105)
    env.pve.fail_next["stop_task"] = ApiError("no such task", status=500)
    vm = env.runner(env.cfg(restore={"restore_timeout_s": 60}), node_shell=env.node_shell).run().vms[0]
    assert vm.failure_code == "RESTORE_TIMEOUT" and vm.cleanup_ok


# ── A6 boot timeout ─────────────────────────────────────────────────────────────
def test_boot_timeout_screenshot_no_checks_cleanup(env: Env):
    add_backup(env.pve, 105)
    env.pve.guest_profile[105] = GuestProfile(never_boots=True)
    env.checks.planned = [C1]
    cfg = env.cfg(vms=[{"vmid": 105, "boot_timeout_s": 30}], **SHOTS)
    report = env.runner(cfg).run()
    vm = report.vms[0]
    assert vm.failure_code == "BOOT_TIMEOUT" and vm.status is Status.FAIL
    assert env.clock.sleeps.count(5) >= 6 and env.clock.t >= 30
    assert env.console.captured == [900105]
    assert vm.screenshots and vm.screenshots[0].endswith("console-900105.png") and os.path.exists(vm.screenshots[0])
    assert step(vm, "screenshot").status is Status.PASS
    assert env.checks.ran == [] and vm.checks == []
    assert "checks" not in [s.name for s in vm.steps]
    assert step(vm, "cleanup").status is Status.PASS and 900105 not in env.pve.vms


def test_boot_fail_when_vm_stops(env: Env):
    class Crashing(FakePve):
        def agent_ping(self, vmid):
            self.vms[vmid].status = "stopped"
            return False

    env.pve = Crashing()
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(**SHOTS)).run().vms[0]
    assert vm.failure_code == "BOOT_FAIL" and vm.status is Status.FAIL
    assert step(vm, "cleanup").status is Status.PASS


def test_boot_waits_for_agent(env: Env):
    add_backup(env.pve, 105)
    env.pve.guest_profile[105] = GuestProfile(boot_polls=3)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.status is Status.PASS and env.clock.sleeps.count(5) == 3


def test_screenshot_capture_failure_is_not_fatal(env: Env):
    add_backup(env.pve, 105)
    env.console.fail = True
    vm = env.runner(env.cfg(**SHOTS_ALWAYS)).run().vms[0]
    assert vm.status is Status.PASS and vm.screenshots == []
    assert step(vm, "screenshot").status is Status.WARN


def test_screenshot_disabled_never_uses_console(env: Env):
    add_backup(env.pve, 105)
    env.pve.guest_profile[105] = GuestProfile(never_boots=True)
    vm = env.runner(env.cfg(screenshot={"when": "always"})).run().vms[0]
    assert vm.failure_code == "BOOT_TIMEOUT" and env.console.captured == []
    assert "screenshot" not in [s.name for s in vm.steps]


def test_screenshot_enabled_without_console_is_skipped(env: Env):
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(**SHOTS_ALWAYS), console=None).run().vms[0]
    assert vm.status is Status.PASS and vm.screenshots == []
    assert "screenshot" not in [s.name for s in vm.steps]


def test_screenshot_failure_only_skipped_on_pass(env: Env):
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(**SHOTS)).run().vms[0]
    assert vm.status is Status.PASS and env.console.captured == []


def test_screenshot_always_on_pass(env: Env):
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(**SHOTS_ALWAYS)).run().vms[0]
    assert vm.status is Status.PASS and len(vm.screenshots) == 1


# ── A7 destroy failure ──────────────────────────────────────────────────────────
def test_destroy_failure_after_retries(env: Env):
    add_backup(env.pve, 105)
    env.pve.destroy_fails.add(900105)
    report = env.runner(env.cfg()).run()
    vm = report.vms[0]
    assert not vm.cleanup_ok and vm.status is Status.ERROR and vm.failure_code == "CLEANUP_FAIL"
    cl = step(vm, "cleanup")
    assert cl.error_code == "CLEANUP_FAIL"
    assert "MANUAL CLEANUP REQUIRED: VM 900105 on restore01" in cl.message
    assert "MANUAL CLEANUP REQUIRED: VM 900105 on restore01" in vm.failure_message
    assert env.clock.sleeps[-3:] == [5, 15, 30]
    assert len(find_calls(env.pve, "destroy_vm")) == 4
    assert report.status is Status.ERROR and exit_code(report) == 3
    sent = env.notifier.reports[0].vms[0]
    assert not sent.cleanup_ok and "MANUAL CLEANUP REQUIRED" in step(sent, "cleanup").message


def test_cleanup_recovers_on_retry(env: Env):
    add_backup(env.pve, 105)
    env.pve.fail_next["destroy_vm"] = ApiError("got timeout", status=500)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.cleanup_ok and vm.status is Status.PASS and env.clock.sleeps[-1] == 5


# ── A9 internal error ───────────────────────────────────────────────────────────
class ExplodingSuite(FakeCheckSuite):
    def plan(self, target, guest, os):
        if target.vmid == 105:
            raise RuntimeError("boom")
        return super().plan(target, guest, os)


def test_unexpected_exception_is_contained(env: Env):
    cfg = two_vms(env)
    env.checks = ExplodingSuite(planned=[C1])
    report = env.runner(cfg).run()
    vm105, vm110 = report.vms
    assert vm105.status is Status.ERROR and vm105.failure_code == "INTERNAL_ERROR"
    assert vm105.failure_message == "RuntimeError: boom"
    assert step(vm105, "checks").error_code == "INTERNAL_ERROR"
    assert step(vm105, "cleanup").status is Status.PASS
    log_text = Path(vm105.log_file).read_text(encoding="utf-8")
    assert "Traceback" in log_text and "RuntimeError: boom" in log_text
    assert vm110.status is Status.PASS and env.checks.ran == [("c1", 900110)]
    assert exit_code(report) == 1


# ── A10 interrupts ──────────────────────────────────────────────────────────────
def test_interrupt_during_checks(env: Env):
    cfg = two_vms(env)
    flag = {"stop": False}

    class StoppingSuite(FakeCheckSuite):
        def run(self, spec, guest, ctx):
            flag["stop"] = True
            return super().run(spec, guest, ctx)

    env.checks = StoppingSuite(planned=[C1, C2])
    report = env.runner(cfg, should_stop=lambda: flag["stop"]).run()
    vm105, vm110 = report.vms
    assert vm105.status is Status.ERROR and vm105.failure_code == "INTERRUPTED"
    assert [c.name for c in vm105.checks] == ["c1"]
    assert step(vm105, "cleanup").status is Status.PASS and 900105 not in env.pve.vms
    assert vm110.status is Status.SKIPPED and vm110.failure_code == "NOT_RUN"
    assert 900110 not in [a[0] for a in find_calls(env.pve, "restore_vm")]
    assert report.interrupted and report.status is Status.ERROR and exit_code(report) == 130
    assert env.notifier.reports == [report]


def test_interrupt_during_restore_wait_stops_task(env: Env):
    add_backup(env.pve, 105)
    env.pve.restore_hangs.add(105)
    pve = env.pve
    stop = lambda: bool(find_calls(pve, "wait_task"))  # noqa: E731
    report = env.runner(env.cfg(), should_stop=stop, node_shell=env.node_shell).run()
    vm = report.vms[0]
    assert vm.failure_code == "INTERRUPTED" and report.interrupted
    assert len(pve.stopped_tasks) == 1 and 900105 not in pve.vms


def test_interrupt_set_by_last_check_is_honoured(env: Env):
    add_backup(env.pve, 105)
    flag = {"stop": False}

    class StopInLast(FakeCheckSuite):
        def run(self, spec, guest, ctx):
            flag["stop"] = True  # e.g. SIGTERM arrives while the only check runs
            return super().run(spec, guest, ctx)

    env.checks = StopInLast(planned=[C1])
    report = env.runner(env.cfg(), should_stop=lambda: flag["stop"]).run()
    vm = report.vms[0]
    assert [c.name for c in vm.checks] == ["c1"]
    assert vm.failure_code == "INTERRUPTED" and step(vm, "checks").error_code == "INTERRUPTED"
    assert step(vm, "cleanup").status is Status.PASS and 900105 not in env.pve.vms
    assert "screenshot" not in [s.name for s in vm.steps]
    assert report.interrupted and exit_code(report) == 130


def test_signal_during_cleanup_does_not_abort_cleanup(env: Env):
    stop = StopFlag()

    class SignalOnDestroy(FakePve):
        def destroy_vm(self, vmid, *, skiplock=False):
            assert stop.in_cleanup
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)
            return super().destroy_vm(vmid, skiplock=skiplock)

    env.pve = SignalOnDestroy()
    cfg = two_vms(env)
    stop.install()
    try:
        report = env.runner(cfg, stop_flag=stop).run()
    finally:
        stop.uninstall()
    vm105, vm110 = report.vms
    assert stop.count == 2 and stop() and not stop.in_cleanup
    assert vm105.status is Status.PASS and vm105.cleanup_ok and step(vm105, "cleanup").status is Status.PASS
    assert 900105 not in env.pve.vms
    assert vm110.failure_code == "NOT_RUN"
    assert report.interrupted and exit_code(report) == 130


# ── A11 sweep ───────────────────────────────────────────────────────────────────
def test_startup_sweep(env: Env):
    add_backup(env.pve, 105)
    env.pve.add_vm(900200, {"name": "left", "tags": "pbv-temp"}, status="running")
    env.pve.add_vm(900300, {"name": "kept", "tags": "pbv-temp;pbv-keep"}, status="running")
    env.pve.add_vm(300, {"name": "prod", "tags": "pbv-temp"})  # outside the range
    report = env.runner(env.cfg()).run()
    assert report.leftovers_swept == [900200]
    assert 900200 not in env.pve.vms and 900300 in env.pve.vms and 300 in env.pve.vms
    assert report.status is Status.PASS


def test_sweep_never_touches_untagged_and_include_kept(env: Env):
    env.pve.add_vm(900400, {"name": "foreign"}, status="running")
    env.pve.add_vm(900300, {"name": "kept", "tags": "pbv-temp;pbv-keep"})
    r = env.runner(env.cfg())
    assert r.sweep() == []
    assert r.sweep(include_kept=True) == [900300]
    assert 900400 in env.pve.vms and env.pve.vms[900400].status == "running"
    touched = {a[0] for n, a in env.pve.calls if n in ("stop_vm", "destroy_vm", "update_vm_config")}
    assert touched == {900300}


def test_sweep_disabled(env: Env):
    add_backup(env.pve, 105)
    env.pve.add_vm(900200, {"name": "left", "tags": "pbv-temp"})
    report = env.runner(env.cfg(run={"sweep_leftovers": False})).run()
    assert report.leftovers_swept == [] and 900200 in env.pve.vms


def test_sweep_failure_is_reported_and_run_continues_with_exit_3(env: Env):
    add_backup(env.pve, 105)
    env.pve.add_vm(900200, {"name": "left", "tags": "pbv-temp"})
    env.pve.add_vm(900300, {"name": "left2", "tags": "pbv-temp"})
    env.pve.destroy_fails.add(900200)
    r = env.runner(env.cfg())
    report = r.run()
    assert report.leftovers_swept == [900300] and report.vms[0].status is Status.PASS
    (failure,) = report.sweep_failures
    assert failure.startswith("900200: CLEANUP_FAIL ") and "lvremove failed" in failure
    assert r.last_sweep_failures == report.sweep_failures
    assert 900200 in env.pve.vms
    assert report.status is Status.ERROR and exit_code(report) == 3
    assert env.notifier.reports[0].sweep_failures == report.sweep_failures


def test_manual_sweep_exposes_failures_and_resets_them(env: Env):
    env.pve.add_vm(900200, {"name": "left", "tags": "pbv-temp"})
    env.pve.destroy_fails.add(900200)
    r = env.runner(env.cfg())
    assert r.sweep() == [] and len(r.last_sweep_failures) == 1
    env.pve.destroy_fails.clear()
    assert r.sweep() == [900200] and r.last_sweep_failures == []


# ── temp VMID / space / backup steps ────────────────────────────────────────────
def test_leftover_on_temp_vmid_is_removed(env: Env):
    add_backup(env.pve, 105)
    env.pve.add_vm(900105, {"name": "old", "tags": "pbv-temp"})
    vm = env.runner(env.cfg(run={"sweep_leftovers": False})).run().vms[0]
    assert vm.status is Status.PASS and "removed leftover" in step(vm, "temp_vmid").message


def test_kept_vm_on_temp_vmid_is_busy(env: Env):
    add_backup(env.pve, 105)
    env.pve.add_vm(900105, {"name": "old", "tags": "pbv-temp;pbv-keep"})
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "TEMP_VMID_BUSY" and vm.status is Status.ERROR
    assert 900105 in env.pve.vms and not find_calls(env.pve, "restore_vm")
    assert step(vm, "cleanup").status is Status.SKIPPED


def test_untagged_vm_on_temp_vmid_is_busy(env: Env):
    add_backup(env.pve, 105)
    r = env.runner(env.cfg())
    env.pve.add_vm(900105, {"name": "foreign"})
    st = r._process_vm(r.cfg.vms[0])  # bypass preflight, which would refuse this node
    assert st.result.failure_code == "TEMP_VMID_BUSY" and 900105 in env.pve.vms
    assert not find_calls(env.pve, "destroy_vm")


def test_insufficient_space(env: Env):
    add_backup(env.pve, 105)
    env.pve.storages["local-lvm"].avail = 1000
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "INSUFFICIENT_SPACE" and vm.status is Status.ERROR
    assert not find_calls(env.pve, "restore_vm")


def test_space_check_skipped_when_unknown(env: Env):
    class NoAvail(FakePve):
        def storage_list(self):
            return [{k: v for k, v in s.items() if k != "avail"} for s in super().storage_list()]

    env.pve = NoAvail()
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg()).run().vms[0]
    assert step(vm, "space").status is Status.SKIPPED and vm.status is Status.PASS


def test_no_backup(env: Env):
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "NO_BACKUP" and vm.status is Status.FAIL
    assert step(vm, "cleanup").status is Status.SKIPPED


def test_backup_too_old_is_not_fatal(env: Env):
    old = int(time.time()) - 50 * 3600
    add_backup(env.pve, 105, ctime=old)
    env.checks.planned = [C1]
    vm = env.runner(env.cfg(restore={"max_backup_age_h": 24})).run().vms[0]
    assert vm.status is Status.FAIL and vm.failure_code == "BACKUP_TOO_OLD"
    assert step(vm, "backup_age").status is Status.FAIL
    assert env.checks.ran == [("c1", 900105)] and step(vm, "cleanup").status is Status.PASS


def test_backup_fresh_enough(env: Env):
    add_backup(env.pve, 105, ctime=int(time.time()) - 3600)
    vm = env.runner(env.cfg(restore={"max_backup_age_h": 24})).run().vms[0]
    assert vm.status is Status.PASS and step(vm, "backup_age").status is Status.PASS


# ── sanitize / start failures ───────────────────────────────────────────────────
def test_sanitize_403_has_privilege_hint(env: Env):
    class Forbidden(FakePve):
        def update_vm_config(self, vmid, set_, delete=()):
            if "net0" in set_:
                raise ApiError("Permission check failed (/vms/900105, VM.Config.HWType)", status=403)
            return super().update_vm_config(vmid, set_, delete)

    env.pve = Forbidden()
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "SANITIZE_FAIL" and vm.status is Status.ERROR
    assert "need root@pam" in vm.failure_message
    assert not find_calls(env.pve, "start_vm") and step(vm, "cleanup").status is Status.PASS
    assert vm.sanitized == []  # nothing was applied


def test_sanitize_warnings_reported(env: Env):
    add_backup(env.pve, 105, config={"name": "x", "scsi1": "ceph:vm-105-disk-1", "hostpci0": "01:00.0"})
    vm = env.runner(env.cfg(**NODE_SHELL)).run().vms[0]
    assert vm.status is Status.PASS
    assert "WARNING: scsi1: disk on missing storage ceph removed" in vm.sanitized
    assert any(s.startswith("hostpci0: removed passthrough") for s in vm.sanitized)


def test_host_pci_removed_through_node_shell(env: Env):
    add_backup(env.pve, 105, config={"name": "gpu", "hostpci0": "host=0000:01:00.0,pcie=1", "serial0": "socket"})
    assert env.pve.token_is_root is False
    report = env.runner(env.cfg(**NODE_SHELL)).run()
    vm = report.vms[0]
    assert vm.status is Status.PASS and report.status is Status.PASS
    assert env.node_shell.qm_calls == [(900105, {}, ["hostpci0"])]
    _mark, api = find_calls(env.pve, "update_vm_config")
    assert "hostpci0" not in api[1] and "hostpci0" not in api[2] and "serial0" not in api[2]
    order = names(env.pve.calls)
    assert order.index("start_vm") > max(i for i, n in enumerate(order) if n == "update_vm_config")
    assert any(s.startswith("hostpci0: removed passthrough") for s in vm.sanitized)
    assert step(vm, "boot").status is Status.PASS and step(vm, "cleanup").status is Status.PASS


def test_host_pci_without_node_shell_needs_root(env: Env):
    add_backup(env.pve, 105, config={"name": "gpu", "hostpci0": "host=0000:01:00.0", "usb1": "host=1234:5678"})
    report = env.runner(env.cfg()).run()
    vm = report.vms[0]
    assert vm.status is Status.FAIL and vm.failure_code == "SANITIZE_NEEDS_ROOT"
    assert vm.failure_message == "needs root@pam for: hostpci0, usb1 — configure [node_shell]"
    sanitize = step(vm, "sanitize")
    assert sanitize.status is Status.FAIL and sanitize.error_code == "SANITIZE_NEEDS_ROOT"
    assert len(find_calls(env.pve, "update_vm_config")) == 1  # only mark; nothing half-applied
    assert not find_calls(env.pve, "start_vm") and env.node_shell.qm_calls == []
    assert step(vm, "cleanup").status is Status.PASS and 900105 not in env.pve.vms
    assert exit_code(report) == 1


@pytest.mark.parametrize("token_is_root", [False, True])
def test_mapped_host_pci_without_node_shell_tries_api(env: Env, token_is_root: bool):
    add_backup(env.pve, 105, config={"name": "gpu", "hostpci0": "mapping=gpu,pcie=1"})
    env.pve.token_is_root = token_is_root
    vm = env.runner(env.cfg()).run().vms[0]
    assert find_calls(env.pve, "update_vm_config")[-1][2] == ("hostpci0",)
    if token_is_root:  # stands in for a token with Mapping.Use
        assert vm.status is Status.PASS
    else:
        assert vm.failure_code == "SANITIZE_FAIL" and "need root@pam" in vm.failure_message
        assert step(vm, "cleanup").status is Status.PASS


def test_node_shell_qm_set_failure(env: Env):
    class QmSetFails(FakeNodeShell):
        def probe(self) -> str:
            return "ok"

        def sysctl(self, key: str) -> str:
            return "restore01" if key == "kernel.hostname" else "1"

    add_backup(env.pve, 105, config={"name": "x", "args": "-cpu host"})
    env.node_shell = QmSetFails(env.pve, fail=True)
    vm = env.runner(env.cfg(**NODE_SHELL)).run().vms[0]
    sanitize = step(vm, "sanitize")
    assert sanitize.status is Status.ERROR and sanitize.error_code == "NODE_SHELL_FAIL"
    assert vm.status is Status.ERROR and vm.failure_code == "NODE_SHELL_FAIL" and "ssh exited 255" in vm.failure_message
    assert env.node_shell.qm_calls == [(900105, {}, ["args"])]
    assert not find_calls(env.pve, "start_vm") and step(vm, "cleanup").status is Status.PASS


def test_node_shell_unused_without_root_keys(env: Env):
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(**NODE_SHELL)).run().vms[0]
    assert vm.status is Status.PASS and env.node_shell.qm_calls == []


def test_node_shell_probe_failure_aborts_run(env: Env):
    add_backup(env.pve, 105)
    env.node_shell.fail = True
    report = env.runner(env.cfg(**NODE_SHELL)).run()
    assert report.vms == [] and report.preflight[-1].name == "node_shell"
    assert report.preflight[-1].error_code == "PREFLIGHT_FAIL" and exit_code(report) == 2
    assert not find_calls(env.pve, "restore_vm")


def test_mark_failure(env: Env):
    add_backup(env.pve, 105)
    env.pve.fail_next["update_vm_config"] = ApiError("locked", status=500)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "SANITIZE_FAIL" and step(vm, "mark").status is Status.ERROR


def test_start_api_error(env: Env):
    add_backup(env.pve, 105)
    env.pve.fail_next["start_vm"] = ApiError("start failed: kvm exited", status=500)
    vm = env.runner(env.cfg()).run().vms[0]
    assert vm.failure_code == "START_FAIL" and vm.status is Status.FAIL
    assert step(vm, "cleanup").status is Status.PASS and 900105 not in env.pve.vms


def test_start_task_failure(env: Env):
    class BadStart(FakePve):
        def start_vm(self, vmid):
            self._record("start_vm", vmid)
            return self._task("qmstart", ok=False, exitstatus="kvm: -device foo: not found")

    env.pve = BadStart()
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(**SHOTS)).run().vms[0]
    assert vm.failure_code == "START_FAIL" and "kvm: -device foo" in vm.failure_message


# ── checks outcomes ─────────────────────────────────────────────────────────────
def test_critical_check_failure(env: Env):
    add_backup(env.pve, 105)
    env.checks = FakeCheckSuite(planned=[C1, C2], results={"c2": Status.FAIL})
    report = env.runner(env.cfg(**SHOTS)).run()
    vm = report.vms[0]
    assert vm.status is Status.FAIL and vm.failure_code == "CHECKS_FAILED"
    assert "c2" in step(vm, "checks").message and len(vm.screenshots) == 1
    assert exit_code(report) == 1


def test_non_critical_check_failure_is_warn(env: Env):
    add_backup(env.pve, 105)
    soft = CheckSpec(type="command", name="soft", params={"argv": ["x"]}, critical=False)
    env.checks = FakeCheckSuite(planned=[C1, soft], results={"soft": Status.ERROR})
    report = env.runner(env.cfg()).run()
    vm = report.vms[0]
    assert vm.status is Status.WARN and vm.failure_code == "" and report.status is Status.WARN
    assert exit_code(report) == 0 and exit_code(report, fail_on_warn=True) == 1


def test_check_plan_warnings_are_logged(env: Env, caplog):
    add_backup(env.pve, 105)
    env.checks.warnings = ["vm 105: mode auto ignores configured checks"]  # type: ignore[attr-defined]
    env.runner(env.cfg()).run()
    assert "mode auto ignores configured checks" in caplog.text


def test_check_context(env: Env):
    add_backup(env.pve, 105, config={"name": "db01"})
    seen = []

    class Ctx(FakeCheckSuite):
        def run(self, spec, guest, ctx):
            seen.append(ctx)
            return super().run(spec, guest, ctx)

    env.checks = Ctx(planned=[C1])
    cfg = env.cfg(vms=[{"vmid": 105, "os": "windows"}])
    env.runner(cfg).run()
    (ctx,) = seen
    assert ctx.vm_name == "db01" and ctx.os.value == "windows" and ctx.temp_vmid == 900105
    assert ctx.work_dir == env.tmp_path / "logs" / "20261007T020000Z-ab12" / "105"
    assert ctx.config_dir == env.tmp_path and ctx.guest_ips == ("10.99.0.5",)


# ── API unreachable ─────────────────────────────────────────────────────────────
def test_two_consecutive_unreachable_vms_abort_the_rest(env: Env):
    class Down(FakePve):
        def list_backups(self, storage):
            self._record("list_backups", storage)
            raise ApiError("connection refused", status=None)

    env.pve = Down()
    cfg = env.cfg(vms=[{"vmid": 105}, {"vmid": 110}, {"vmid": 120}])
    report = env.runner(cfg).run()
    codes = [(v.vmid, v.status, v.failure_code) for v in report.vms]
    assert codes[2] == (120, Status.ERROR, "API_UNREACHABLE")
    assert codes[0][1] is Status.ERROR and codes[1][1] is Status.ERROR
    assert len(find_calls(env.pve, "list_backups")) == 2
    assert len(env.notifier.vm_results) == 2


def test_single_unreachable_vm_does_not_abort(env: Env):
    for v in (105, 110, 120):
        add_backup(env.pve, v)
    env.pve.fail_next["list_backups"] = ApiError("connection reset", status=None)
    cfg = env.cfg(vms=[{"vmid": 105}, {"vmid": 110}, {"vmid": 120}])
    report = env.runner(cfg).run()
    assert [v.status for v in report.vms] == [Status.ERROR, Status.PASS, Status.PASS]


# ── keep_on_failure ─────────────────────────────────────────────────────────────
def test_keep_on_failure(env: Env):
    add_backup(env.pve, 105)
    env.checks = FakeCheckSuite(planned=[C1], results={"c1": Status.FAIL})
    cfg = env.cfg(restore={"keep_on_failure": True})
    report = env.runner(cfg).run()
    vm = report.vms[0]
    assert vm.status is Status.FAIL and vm.cleanup_ok and "kept for debugging" in vm.sanitized
    assert step(vm, "cleanup").status is Status.SKIPPED
    kept = env.pve.vms[900105]
    assert kept.status == "running" and kept.config["tags"] == "pbv-temp;pbv-keep"
    assert exit_code(report) == 1
    r = env.runner(cfg)
    assert r.sweep() == [] and r.sweep(include_kept=True) == [900105]


def test_keep_on_failure_does_not_keep_passing_vms(env: Env):
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(restore={"keep_on_failure": True})).run().vms[0]
    assert vm.status is Status.PASS and 900105 not in env.pve.vms


# ── notifications / preflight in run ────────────────────────────────────────────
def test_notifier_errors_are_recorded(env: Env):
    add_backup(env.pve, 105)
    bad = RecordingNotifier("email", raise_exc=PbvError("smtp refused", code="NOTIFY_FAIL"))
    buggy = RecordingNotifier("ntfy", raise_exc=ValueError("oops"))
    report = env.runner(env.cfg(), notifiers=[bad, buggy, env.notifier]).run()
    assert report.status is Status.PASS and exit_code(report) == 0
    assert report.notify_errors == [
        "email: NOTIFY_FAIL smtp refused",
        "ntfy: NOTIFY_FAIL ValueError: oops",
        "email: NOTIFY_FAIL smtp refused",
        "ntfy: NOTIFY_FAIL ValueError: oops",
    ]
    assert env.notifier.reports == [report] and len(env.notifier.vm_results) == 1


def test_preflight_failure_in_run(env: Env):
    env.pve.cluster.append({"type": "cluster", "name": "prod"})
    add_backup(env.pve, 105)
    report = env.runner(env.cfg()).run()
    assert report.status is Status.ERROR and report.vms == []
    assert report.preflight[-1].error_code == "PREFLIGHT_FAIL" and report.preflight[-1].name == "standalone"
    assert not find_calls(env.pve, "restore_vm") and not find_calls(env.pve, "list_vms")
    assert env.notifier.reports == [report]
    assert exit_code(report) == 2


def test_preflight_internal_error_in_run(env: Env):
    class Weird(FakePve):
        def list_vms(self):
            return [{"name": "no vmid key"}]

    env.pve = Weird()
    report = env.runner(env.cfg()).run()
    assert report.preflight[-1].error_code == "INTERNAL_ERROR" and exit_code(report) == 2


def test_unknown_vmid_selection_error(env: Env):
    report = env.runner(env.cfg()).run(vmids=[5])
    assert report.preflight[-1].name == "targets" and report.preflight[-1].error_code == "CONFIG_ERROR"
    assert exit_code(report) == 2


# ── logging ─────────────────────────────────────────────────────────────────────
def test_log_files_and_no_handler_leak(env: Env):
    cfg = two_vms(env)
    pbv_logger = logging.getLogger("pbv")
    trace = logging.getLogger("pbv.orchestrator.trace")
    before = (list(pbv_logger.handlers), list(trace.handlers))
    report = env.runner(cfg).run()
    assert (pbv_logger.handlers, trace.handlers) == before
    run_dir = env.tmp_path / "logs" / "20261007T020000Z-ab12"
    run_log = (run_dir / "run.log").read_text()
    assert "RESTORE_OK vmid=105 temp=900105" in run_log and "RESTORE_OK vmid=110" in run_log
    vm105_log = (run_dir / "105" / "vm.log").read_text()
    assert "VM_START vmid=105" in vm105_log and "vmid=110" not in vm105_log
    assert report.vms[0].log_file == str(run_dir / "105" / "vm.log")


def test_unwritable_log_dir_does_not_break_run(env: Env, tmp_path):
    add_backup(env.pve, 105)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    report = env.runner(env.cfg(), log_dir=blocker / "sub").run()
    assert report.status is Status.PASS and report.vms[0].log_file == ""


def test_log_dir_defaults_to_config(env: Env):
    add_backup(env.pve, 105)
    cfg = env.cfg()
    r = env.runner(cfg)
    assert r.log_dir == cfg.run.log_dir


def test_secrets_never_logged(env: Env, caplog):
    add_backup(env.pve, 105)
    env.pve.destroy_fails.add(900105)
    report = env.runner(env.cfg()).run()
    run_log = (env.tmp_path / "logs" / report.run_id / "run.log").read_text()
    assert "00000000-1111" not in run_log and "00000000-1111" not in caplog.text


# ── targets / plan ──────────────────────────────────────────────────────────────
def test_resolve_targets_listed_and_vmids(env: Env):
    cfg = env.cfg(vms=[{"vmid": 110, "name": "b"}, {"vmid": 105, "name": "a"}])
    r = env.runner(cfg)
    assert [t.vmid for t in r.resolve_targets()] == [110, 105]
    got = r.resolve_targets([105, 120, 105])
    assert [t.vmid for t in got] == [105, 120]
    assert got[0].name_hint == "a" and got[1].mode == "auto" and got[1].temp_vmid == 900120


def test_resolve_targets_all(env: Env):
    for v in (120, 105, 110, 105):
        add_backup(env.pve, v, ctime=NOW_CTIME + v)
    env.pve.add_backup(BackupRef(volid="pbs:backup/vm/50/1", vmid=50, ctime=1, size=1))  # outside 100..base
    cfg = env.cfg(vms=[], run={"selection": "all", "exclude": [110]})
    assert [t.vmid for t in env.runner(cfg).resolve_targets()] == [105, 120]


def test_plan_is_read_only(env: Env):
    ref = add_backup(env.pve, 105)
    cfg = env.cfg(vms=[{"vmid": 105}, {"vmid": 110}])
    plan = env.runner(cfg).plan()
    assert [(t.vmid, b) for t, b in plan] == [(105, ref), (110, None)]
    assert set(names(env.pve.calls)) <= {"list_backups"}


# ── exit codes ──────────────────────────────────────────────────────────────────
def _report(*vms: VmResult, **kw: Any) -> RunReport:
    base = {"run_id": "r", "target_node": "n", "started_at": "", "finished_at": "", "duration_s": 0.0}
    status = kw.pop("status", Status.worst([v.status for v in vms], Status.PASS))
    return RunReport(**base, status=status, vms=list(vms), **kw)


def _vm(status: Status, cleanup_ok: bool = True) -> VmResult:
    return VmResult(
        vmid=105, temp_vmid=900105, name="x", status=status, started_at="", duration_s=0, cleanup_ok=cleanup_ok
    )


@pytest.mark.parametrize(
    ("report", "fail_on_warn", "code"),
    [
        (_report(_vm(Status.PASS)), False, 0),
        (_report(_vm(Status.WARN)), False, 0),
        (_report(_vm(Status.WARN)), True, 1),
        (_report(_vm(Status.FAIL)), False, 1),
        (_report(_vm(Status.ERROR)), False, 1),
        (_report(_vm(Status.FAIL), _vm(Status.ERROR, cleanup_ok=False)), False, 3),
        (_report(_vm(Status.ERROR, cleanup_ok=False), interrupted=True), False, 3),  # 3 > 130
        (_report(_vm(Status.ERROR), sweep_failures=["900200: CLEANUP_FAIL x"], interrupted=True), False, 3),
        (_report(_vm(Status.ERROR), interrupted=True), False, 130),
        (
            _report(
                status=Status.ERROR,
                preflight=[StepResult("node", Status.FAIL, "", 0, "x", "PREFLIGHT_FAIL")],
                interrupted=True,
            ),
            False,
            130,
        ),
        (
            _report(status=Status.ERROR, preflight=[StepResult("node", Status.FAIL, "", 0, "x", "PREFLIGHT_FAIL")]),
            False,
            2,
        ),
        (_report(), False, 0),
        (_report(_vm(Status.PASS), sweep_failures=["900200: CLEANUP_FAIL x"]), False, 3),
    ],
)
def test_exit_code(report, fail_on_warn, code):
    assert exit_code(report, fail_on_warn=fail_on_warn) == code


# ── fix wave: locked VMs (SPEC §4 step 1) ───────────────────────────────────────
def test_locked_vm_without_node_shell_fails_cleanup_with_vm_locked(env: Env):
    add_backup(env.pve, 105)
    env.pve.restore_fails[105] = "unable to restore: chunk missing"
    report = env.runner(env.cfg()).run()
    vm = report.vms[0]
    cleanup = step(vm, "cleanup")
    assert cleanup.status is Status.ERROR and cleanup.error_code == "CLEANUP_FAIL" and not vm.cleanup_ok
    assert "VM_LOCKED" in cleanup.message and "locked (create)" in cleanup.message
    assert "configure [node_shell] or run `qm unlock 900105`" in cleanup.message
    assert "MANUAL CLEANUP REQUIRED: VM 900105 on restore01" in cleanup.message
    assert env.clock.sleeps == [5, 15, 30]  # retries/backoff unchanged
    assert not find_calls(env.pve, "destroy_vm") and not find_calls(env.pve, "stop_vm")
    assert 900105 in env.pve.vms and report.status is Status.ERROR and exit_code(report) == 3


def test_unlock_failure_is_retried_then_cleanup_fail(env: Env):
    add_backup(env.pve, 105)
    env.pve.restore_fails[105] = "unable to restore: chunk missing"

    class UnlockFails(FakeNodeShell):
        def unlock(self, vmid: int) -> None:
            self.unlocks.append(vmid)
            raise PbvError("node shell: ssh exited 255", code="NODE_SHELL_FAIL")

    env.node_shell = UnlockFails(env.pve)
    vm = env.runner(env.cfg(), node_shell=env.node_shell).run().vms[0]
    assert env.node_shell.unlocks == [900105] * 4
    assert not vm.cleanup_ok and "NODE_SHELL_FAIL" in step(vm, "cleanup").message


def test_unlocked_vm_is_not_unlocked(env: Env):
    add_backup(env.pve, 105)
    vm = env.runner(env.cfg(), node_shell=env.node_shell).run().vms[0]
    assert vm.status is Status.PASS and env.node_shell.unlocks == []


def test_sweep_unlocks_locked_leftover(env: Env):
    env.pve.add_vm(900200, {"name": "left", "tags": "pbv-temp", "lock": "backup"}, status="running")
    r = env.runner(env.cfg(), node_shell=env.node_shell)
    assert r.sweep() == [900200] and env.node_shell.unlocks == [900200]


def test_unlock_never_touches_foreign_vm(env: Env):
    env.pve.add_vm(900200, {"name": "foreign", "lock": "backup"})
    r = env.runner(env.cfg(), node_shell=env.node_shell)
    with pytest.raises(SafetyError):
        r._destroy(900200)
    assert env.node_shell.unlocks == [] and 900200 in env.pve.vms


# ── fix wave: cleanup in finally ────────────────────────────────────────────────
class _RaisingSuite(FakeCheckSuite):
    def __init__(self, exc: BaseException) -> None:
        super().__init__(planned=[C1])
        self.exc = exc

    def run(self, spec, guest, ctx):
        raise self.exc


def test_keyboard_interrupt_in_vm_cleans_up_and_returns_interrupted_report(env: Env):
    cfg = two_vms(env)
    env.checks = _RaisingSuite(KeyboardInterrupt())
    report = env.runner(cfg).run()
    vm105, vm110 = report.vms
    assert vm105.status is Status.ERROR and vm105.failure_code == "INTERRUPTED"
    assert step(vm105, "cleanup").status is Status.PASS and 900105 not in env.pve.vms
    assert "screenshot" not in [s.name for s in vm105.steps]
    assert vm110.failure_code == "NOT_RUN" and vm110.status is Status.SKIPPED
    assert report.interrupted and report.status is Status.ERROR and exit_code(report) == 130
    assert env.notifier.reports == [report]


@pytest.mark.parametrize("exc", [SystemExit(1), GeneratorExit()], ids=["SystemExit", "GeneratorExit"])
def test_other_base_exceptions_clean_up_then_propagate(env: Env, exc: BaseException):
    add_backup(env.pve, 105)
    env.checks = _RaisingSuite(exc)
    with pytest.raises(type(exc)):
        env.runner(env.cfg()).run()
    assert 900105 not in env.pve.vms
    assert ("destroy_vm", (900105, False)) in env.pve.calls


def test_screenshot_bug_is_contained(env: Env):
    add_backup(env.pve, 105)
    env.checks = FakeCheckSuite(planned=[C1], results={"c1": Status.FAIL})
    r = env.runner(env.cfg(**SHOTS))

    def boom(st):
        raise RuntimeError("screenshot bug")

    r._screenshot = boom
    report = r.run()
    vm = report.vms[0]
    shot = step(vm, "screenshot")
    assert shot.status is Status.WARN and "screenshot bug" in shot.message
    assert vm.failure_code == "CHECKS_FAILED" and step(vm, "cleanup").status is Status.PASS
    assert 900105 not in env.pve.vms and env.notifier.reports == [report]


def test_keyboard_interrupt_in_screenshot_still_cleans_up(env: Env):
    add_backup(env.pve, 105)
    r = env.runner(env.cfg(**SHOTS_ALWAYS))

    def interrupt(st):
        raise KeyboardInterrupt

    r._screenshot = interrupt
    report = r.run()
    assert report.interrupted and report.vms[0].failure_code == "INTERRUPTED"
    assert 900105 not in env.pve.vms


# ── fix wave: keep_on_failure only for sanitized VMs ────────────────────────────
def test_keep_on_failure_destroys_vm_whose_sanitize_failed(env: Env):
    add_backup(env.pve, 105, config={"name": "db", "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0", "args": "-x"})
    vm = env.runner(env.cfg(restore={"keep_on_failure": True})).run().vms[0]
    assert vm.failure_code == "SANITIZE_NEEDS_ROOT"
    cleanup = step(vm, "cleanup")
    assert cleanup.status is Status.PASS and "not kept: sanitize failed" in cleanup.message
    assert "not kept: sanitize failed" in vm.sanitized and "kept for debugging" not in vm.sanitized
    assert 900105 not in env.pve.vms


def test_keep_on_failure_destroys_vm_when_sanitize_did_not_run(env: Env):
    add_backup(env.pve, 105)
    env.pve.fail_next["update_vm_config"] = ApiError("mark failed", status=500)
    vm = env.runner(env.cfg(restore={"keep_on_failure": True})).run().vms[0]
    assert vm.status is Status.ERROR and "not kept: sanitize did not run" in vm.sanitized
    assert 900105 not in env.pve.vms


# ── fix wave: late interrupts ───────────────────────────────────────────────────
def test_signal_during_final_cleanup_marks_report_interrupted(env: Env):
    flag = {"stop": False}

    class SignalOnDestroy(FakePve):
        def destroy_vm(self, vmid, *, skiplock=False):
            flag["stop"] = True
            return super().destroy_vm(vmid, skiplock=skiplock)

    env.pve = SignalOnDestroy()
    add_backup(env.pve, 105)
    report = env.runner(env.cfg(), should_stop=lambda: flag["stop"]).run()
    assert report.vms[0].status is Status.PASS and 900105 not in env.pve.vms
    assert report.interrupted and report.status is Status.ERROR and exit_code(report) == 130


def test_signal_during_startup_sweep_runs_no_vm(env: Env):
    flag = {"stop": False}

    class SignalOnDestroy(FakePve):
        def destroy_vm(self, vmid, *, skiplock=False):
            flag["stop"] = True
            return super().destroy_vm(vmid, skiplock=skiplock)

    env.pve = SignalOnDestroy()
    add_backup(env.pve, 105)
    env.pve.add_vm(900200, {"name": "left", "tags": "pbv-temp"})
    report = env.runner(env.cfg(), should_stop=lambda: flag["stop"]).run()
    assert report.leftovers_swept == [900200]
    assert report.vms[0].failure_code == "NOT_RUN" and not find_calls(env.pve, "restore_vm")
    assert report.interrupted and exit_code(report) == 130


def test_stop_flag_count_counts_as_stop(env: Env):
    add_backup(env.pve, 105)
    stop = StopFlag()
    stop.count = 1  # a signal was recorded even though ``stopped`` was reset
    report = env.runner(env.cfg(), stop_flag=stop).run()
    assert report.interrupted and report.vms[0].failure_code == "NOT_RUN"


def test_leftover_on_interrupt_exits_3(env: Env):
    add_backup(env.pve, 105)
    flag = {"stop": False}

    class StopThenFailDestroy(FakeCheckSuite):
        def run(self, spec, guest, ctx):
            flag["stop"] = True
            env.pve.destroy_fails.add(900105)
            return super().run(spec, guest, ctx)

    env.checks = StopThenFailDestroy(planned=[C1])
    report = env.runner(env.cfg(), should_stop=lambda: flag["stop"]).run()
    assert report.interrupted and not report.vms[0].cleanup_ok
    assert exit_code(report) == 3
