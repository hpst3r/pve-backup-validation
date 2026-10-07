"""A15: ``when`` semantics and deterministic rendering (snapshot-style)."""

from __future__ import annotations

import pytest

from pbv.core import NotifyWhen, Status
from pbv.notify import render_subject, render_text, render_vm_subject, render_vm_text, should_send
from pbv.notify.render import (
    TRUNCATION_NOTE,
    cleanup_failed,
    run_needs_attention,
    should_send_run,
    truncate_utf16,
    utf16_len,
)

from .conftest import check, make_report, make_vm, step

S = Status
W = NotifyWhen


@pytest.mark.parametrize(
    ("when", "status", "interrupted", "cleanup_failed", "expected"),
    [
        (W.ALWAYS, S.PASS, False, False, True),
        (W.ALWAYS, S.ERROR, True, True, True),
        (W.NEVER, S.PASS, False, False, False),
        (W.NEVER, S.FAIL, True, True, False),
        (W.FAILURE, S.PASS, False, False, False),
        (W.FAILURE, S.SKIPPED, False, False, False),
        (W.FAILURE, S.WARN, False, False, True),
        (W.FAILURE, S.FAIL, False, False, True),
        (W.FAILURE, S.ERROR, False, False, True),
        (W.FAILURE, S.PASS, True, False, True),
        (W.FAILURE, S.PASS, False, True, True),
    ],
)
def test_should_send_truth_table(
    when: NotifyWhen, status: Status, interrupted: bool, cleanup_failed: bool, expected: bool
) -> None:
    assert should_send(when, status, interrupted=interrupted, cleanup_failed=cleanup_failed) is expected


def _fail_report():
    return make_report(
        [
            make_vm(101, checks=[check("systemd:sshd", S.PASS, "active")]),
            make_vm(
                105,
                S.FAIL,
                name="web01",
                failure_code="CHECKS_FAILED",
                failure_message="1 critical check failed",
                checks=[
                    check("systemd:nginx", S.PASS, "active"),
                    check("http:80", S.FAIL, "HTTP 500"),
                    check("tcp_listen:22", S.SKIPPED, "only_os windows"),
                    check("log_scan:app", S.WARN, "3 matches > 0"),
                ],
                sanitized=["a", "b", "c"],
                screenshots=["/var/log/pbv/r/105/console.png"],
                log_file="/var/log/pbv/r/105/vm.log",
            ),
            make_vm(102),
            make_vm(103),
        ]
    )


def test_fail_report_snapshot() -> None:
    report = _fail_report()
    assert render_subject(report) == "[pbv] FAIL 1/4 VMs on restore01 (3 pass, 1 fail)"
    text = render_text(report)
    expected_head = """\
pbv run 20261007T020000Z-ab12 on restore01: FAIL
Started:  2026-10-07T02:00:00Z
Finished: 2026-10-07T02:10:00Z (duration 10m 00s)
VMs: 4 (3 pass, 1 fail)

[FAIL] web01 — vmid 105, temp 900105, 1m 21s
  Backup: pbs:backup/vm/105/2026-10-06T02:00:00Z (age 24.0 h, 12.3 GiB)
  Failure: CHECKS_FAILED — 1 critical check failed
  ✗ http:80 — HTTP 500
  ! log_scan:app — 3 matches > 0
  ✓ systemd:nginx — active
  - tcp_listen:22 — only_os windows
  Sanitize: 3 change(s)
  Screenshots: 1
  Cleanup: ok
  Log: /var/log/pbv/r/105/vm.log

[PASS] vm101 — vmid 101, temp 900101, 1m 21s
  Backup: pbs:backup/vm/101/2026-10-06T02:00:00Z (age 24.0 h, 12.3 GiB)
  ✓ systemd:sshd — active
  Cleanup: ok

[PASS] vm102 — vmid 102, temp 900102, 1m 21s
"""
    assert text.startswith(expected_head)
    assert text == render_text(_fail_report())  # deterministic


def test_pass_report_snapshot() -> None:
    report = make_report([make_vm(101), make_vm(102)])
    assert render_subject(report) == "[pbv] PASS 2/2 VMs on restore01"
    assert render_subject(report, "") == "PASS 2/2 VMs on restore01"
    assert render_text(report) == (
        "pbv run 20261007T020000Z-ab12 on restore01: PASS\n"
        "Started:  2026-10-07T02:00:00Z\n"
        "Finished: 2026-10-07T02:10:00Z (duration 10m 00s)\n"
        "VMs: 2 (2 pass)\n"
        "\n"
        "[PASS] vm101 — vmid 101, temp 900101, 1m 21s\n"
        "  Backup: pbs:backup/vm/101/2026-10-06T02:00:00Z (age 24.0 h, 12.3 GiB)\n"
        "  Cleanup: ok\n"
        "\n"
        "[PASS] vm102 — vmid 102, temp 900102, 1m 21s\n"
        "  Backup: pbs:backup/vm/102/2026-10-06T02:00:00Z (age 24.0 h, 12.3 GiB)\n"
        "  Cleanup: ok\n"
    )


def _cleanup_failed_report():
    return make_report(
        [
            make_vm(101),
            make_vm(
                107,
                S.ERROR,
                name="db01",
                backup=None,
                failure_code="RESTORE_FAIL",
                failure_message="exit code 1",
                steps=[
                    step("restore", S.FAIL, "RESTORE_FAIL", "exit code 1"),
                    step("cleanup", S.ERROR, "CLEANUP_FAIL", "destroy failed after 3 attempts"),
                ],
                cleanup_ok=False,
            ),
        ],
        notify_errors=["ntfy: NOTIFY_FAIL ntfy: HTTP 403 Forbidden"],
        leftovers_swept=[900104, 900106],
    )


def test_cleanup_failed_snapshot() -> None:
    report = _cleanup_failed_report()
    assert render_subject(report) == "[pbv] CLEANUP-FAILED ERROR 1/2 VMs on restore01 (1 pass, 1 error)"
    assert render_text(report) == (
        "pbv run 20261007T020000Z-ab12 on restore01: CLEANUP-FAILED ERROR\n"
        "Started:  2026-10-07T02:00:00Z\n"
        "Finished: 2026-10-07T02:10:00Z (duration 10m 00s)\n"
        "VMs: 2 (1 pass, 1 error)\n"
        "\n"
        "MANUAL CLEANUP REQUIRED: VM 900107 (from 107 db01) on restore01\n"
        "\n"
        "[ERROR] db01 — vmid 107, temp 900107, 1m 21s\n"
        "  Backup: none\n"
        "  Failure: RESTORE_FAIL — exit code 1\n"
        "  ✗ step cleanup: ERROR CLEANUP_FAIL — destroy failed after 3 attempts\n"
        "  Cleanup: FAILED — temp VM 900107 may still exist\n"
        "\n"
        "[PASS] vm101 — vmid 101, temp 900101, 1m 21s\n"
        "  Backup: pbs:backup/vm/101/2026-10-06T02:00:00Z (age 24.0 h, 12.3 GiB)\n"
        "  Cleanup: ok\n"
        "\n"
        "Notification errors:\n"
        "  - ntfy: NOTIFY_FAIL ntfy: HTTP 403 Forbidden\n"
        "\n"
        "Leftovers swept: 900104, 900106\n"
    )


def test_manual_cleanup_lines_come_before_vm_blocks() -> None:
    report = make_report(
        [make_vm(102, S.PASS, cleanup_ok=False), make_vm(101, S.FAIL, cleanup_ok=False)], status=S.ERROR
    )
    lines = render_text(report).splitlines()
    manual = [i for i, ln in enumerate(lines) if ln.startswith("MANUAL CLEANUP REQUIRED")]
    first_block = next(i for i, ln in enumerate(lines) if ln.startswith("["))
    assert len(manual) == 2 and max(manual) < first_block
    # cleanup-failed VMs first, then by severity: 101 (fail) before 102 (pass)
    assert lines[manual[0]] == "MANUAL CLEANUP REQUIRED: VM 900101 (from 101 vm101) on restore01"


def test_cleanup_failure_on_passing_vm_marks_subject() -> None:
    report = make_report([make_vm(101, cleanup_ok=False)], status=S.PASS)
    assert render_subject(report) == "[pbv] CLEANUP-FAILED PASS 0/1 VMs on restore01"


def test_interrupted_snapshot() -> None:
    report = make_report([make_vm(101), make_vm(102, S.FAIL)], status=S.ERROR, interrupted=True)
    assert render_subject(report) == "[pbv] INTERRUPTED 1/2 VMs on restore01 (1 pass, 1 fail)"
    text = render_text(report)
    assert text.splitlines()[0] == "pbv run 20261007T020000Z-ab12 on restore01: INTERRUPTED"
    assert "Run was INTERRUPTED; remaining VMs were not tested." in text


def test_warn_and_empty_runs() -> None:
    warn = make_report([make_vm(101), make_vm(102, S.WARN)])
    assert render_subject(warn) == "[pbv] WARN 1/2 VMs on restore01 (1 pass, 1 warn)"
    empty = make_report([], status=S.ERROR, preflight=[step("bridge", S.FAIL, "PREFLIGHT_FAIL", "has ports")])
    assert render_subject(empty) == "[pbv] ERROR 0/0 VMs on restore01"
    text = render_text(empty)
    assert "VMs: 0\n" in text
    assert "Preflight:\n  ✗ step bridge: FAIL PREFLIGHT_FAIL — has ports\n" in text


def test_backup_unknown_size_and_bad_timestamp() -> None:
    vm = make_vm(101)
    vm.backup = type(vm.backup)(volid="pbs:x", vmid=101, ctime=0, size=0)
    report = make_report([vm], started_at="garbage")
    assert "  Backup: pbs:x (size unknown)\n" in render_text(report)


def test_long_durations() -> None:
    report = make_report([make_vm(101, duration_s=42.4)], duration_s=3 * 3600 + 5 * 60)
    text = render_text(report)
    assert "(duration 3h 05m)" in text
    assert "temp 900101, 42s" in text


def test_truncation() -> None:
    report = _fail_report()
    full = render_text(report)
    cut = render_text(report, max_chars=300)
    assert len(cut) == 300
    assert cut.endswith(TRUNCATION_NOTE)
    assert full.startswith(cut[: -len(TRUNCATION_NOTE)])
    assert render_text(report, max_chars=len(full)) == full


def test_vm_text_and_subject() -> None:
    report = _cleanup_failed_report()
    vm = report.vms[1]
    assert render_vm_subject(vm, report) == "[pbv] CLEANUP-FAILED ERROR db01 (107) on restore01"
    text = render_vm_text(vm, report)
    assert text.splitlines()[:3] == [
        "pbv run 20261007T020000Z-ab12 on restore01: VM db01 (107) CLEANUP-FAILED ERROR",
        "MANUAL CLEANUP REQUIRED: VM 900107 (from 107 db01) on restore01",
        "",
    ]
    assert "[ERROR] db01 — vmid 107" in text
    ok = make_vm(101, name="")
    assert render_vm_subject(ok, report, "[x]") == "[x] PASS vm101 (101) on restore01"


def _sweep_report(status: S = S.ERROR, vms: list | None = None):
    return make_report(
        vms if vms is not None else [make_vm(105)],
        status=status,
        sweep_failures=["900777: CLEANUP_FAIL destroy task failed", "900778: TIMEOUT stop timed out"],
    )


def test_sweep_failures_render_as_manual_cleanup_at_top() -> None:
    report = _sweep_report(vms=[make_vm(105), make_vm(106, S.FAIL, cleanup_ok=False)])
    lines = render_text(report).splitlines()
    assert lines[0] == "pbv run 20261007T020000Z-ab12 on restore01: CLEANUP-FAILED ERROR"
    manual = [ln for ln in lines if ln.startswith("MANUAL CLEANUP REQUIRED")]
    assert manual == [
        "MANUAL CLEANUP REQUIRED: VM 900777 on restore01 (startup sweep: CLEANUP_FAIL destroy task failed)",
        "MANUAL CLEANUP REQUIRED: VM 900778 on restore01 (startup sweep: TIMEOUT stop timed out)",
        "MANUAL CLEANUP REQUIRED: VM 900106 (from 106 vm106) on restore01",
    ]
    first_block = next(i for i, ln in enumerate(lines) if ln.startswith("["))
    assert lines.index(manual[-1]) < first_block


def test_sweep_failures_mark_subject() -> None:
    assert render_subject(_sweep_report()) == "[pbv] CLEANUP-FAILED ERROR 0/1 VMs on restore01"
    assert render_subject(_sweep_report(vms=[])) == "[pbv] CLEANUP-FAILED ERROR 0/0 VMs on restore01"


def test_sweep_failure_gating_and_attention() -> None:
    # Even a PASS-status report must alert on 'failure' when the sweep left VMs behind.
    report = _sweep_report(status=S.PASS)
    assert cleanup_failed(report) and run_needs_attention(report)
    assert should_send_run(NotifyWhen.FAILURE, report)
    assert not should_send_run(NotifyWhen.NEVER, report)
    assert not should_send_run(NotifyWhen.FAILURE, make_report([make_vm(1)], status=S.PASS))


def test_malformed_sweep_entry_still_rendered() -> None:
    report = make_report([], status=S.ERROR, sweep_failures=["garbage without separator"])
    expected = "MANUAL CLEANUP REQUIRED: VM ? on restore01 (startup sweep: garbage without separator)"
    assert expected in render_text(report)


def test_truncate_utf16_never_splits_surrogate_pairs() -> None:
    assert utf16_len("a😀é") == 4
    assert truncate_utf16("😀" * 10, 20) == "😀" * 10
    note = utf16_len(TRUNCATION_NOTE)
    out = truncate_utf16("😀" * 100, note + 5)  # odd budget: 2 emoji fit (4 units), the 3rd would split
    assert out == "😀😀" + TRUNCATION_NOTE
    out.encode("utf-8")  # strict: raises on a lone surrogate
    assert truncate_utf16("abc", 1) == TRUNCATION_NOTE
