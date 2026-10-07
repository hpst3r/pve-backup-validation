"""Deterministic plain-text rendering of run and VM results (SPEC §6).

Everything here is a pure function of the report, so notifications are stable
and testable with snapshot-style asserts. Problems always come first: manual
cleanup lines head the body, and VMs and checks are sorted by severity.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pbv.core import BackupRef, NotifyWhen, RunReport, Status, StepResult, VmResult

TRUNCATION_NOTE = "\n…(truncated, see JSON report)"

_PROBLEM = frozenset({Status.WARN, Status.FAIL, Status.ERROR})
_SYMBOL = {
    Status.PASS: "✓",
    Status.WARN: "!",
    Status.FAIL: "✗",
    Status.ERROR: "✗",
    Status.SKIPPED: "-",
}
_COUNT_ORDER = (Status.PASS, Status.WARN, Status.FAIL, Status.ERROR, Status.SKIPPED)
_GIB = 1024**3


# ── gating ────────────────────────────────────────────────────────────────────


def should_send(
    when: NotifyWhen,
    status: Status,
    *,
    interrupted: bool = False,
    cleanup_failed: bool = False,
) -> bool:
    """Return True when a notifier configured with ``when`` should fire.

    ``failure`` matches warn/fail/error, an interrupted run, or any VM whose
    cleanup failed (even if its status were somehow PASS).
    """
    if when == NotifyWhen.ALWAYS:
        return True
    if when == NotifyWhen.NEVER:
        return False
    return is_problem(status) or interrupted or cleanup_failed


def is_problem(status: Status) -> bool:
    """True for statuses worse than PASS (warn, fail, error)."""
    return status in _PROBLEM


def cleanup_failed(report: RunReport) -> bool:
    """True if a temporary VM may have been left behind (by a VM test or the startup sweep)."""
    return bool(report.sweep_failures) or any(not vm.cleanup_ok for vm in report.vms)


def run_needs_attention(report: RunReport) -> bool:
    """Whether the run as a whole counts as a failure for priorities/tags."""
    return is_problem(report.status) or report.interrupted or cleanup_failed(report)


def vm_needs_attention(vm: VmResult) -> bool:
    """Whether a single VM counts as a failure for priorities/tags."""
    return is_problem(vm.status) or not vm.cleanup_ok


def should_send_run(when: NotifyWhen, report: RunReport) -> bool:
    """:func:`should_send` applied to a whole run."""
    return should_send(when, report.status, interrupted=report.interrupted, cleanup_failed=cleanup_failed(report))


def should_send_vm(when: NotifyWhen, vm: VmResult) -> bool:
    """:func:`should_send` applied to one VM."""
    return should_send(when, vm.status, cleanup_failed=not vm.cleanup_ok)


# ── subjects ──────────────────────────────────────────────────────────────────


def _label(status: Status, *, interrupted: bool = False, cleanup_bad: bool = False) -> str:
    label = "INTERRUPTED" if interrupted else status.value.upper()
    return f"CLEANUP-FAILED {label}" if cleanup_bad else label


def _counts_text(counts: dict[str, int]) -> str:
    return ", ".join(f"{counts[s.value]} {s.value}" for s in _COUNT_ORDER if counts.get(s.value))


def _join_prefix(prefix: str, text: str) -> str:
    return f"{prefix} {text}" if prefix else text


def render_subject(report: RunReport, prefix: str = "[pbv]") -> str:
    """One-line subject, e.g. ``[pbv] FAIL 1/4 VMs on restore01 (3 pass, 1 fail)``.

    A passing run shows ``passed/total``; anything else shows
    ``problems/total``. The breakdown is omitted when every VM passed.
    """
    counts = report.counts
    total = len(report.vms)
    bad = cleanup_failed(report)
    label = _label(report.status, interrupted=report.interrupted, cleanup_bad=bad)
    if report.status == Status.PASS and not report.interrupted and not bad:
        num = counts[Status.PASS.value]
    else:
        num = sum(counts[s.value] for s in _PROBLEM)
    text = f"{label} {num}/{total} VMs on {report.target_node}"
    if total and counts[Status.PASS.value] != total:
        text += f" ({_counts_text(counts)})"
    return _join_prefix(prefix, text)


def render_vm_subject(vm: VmResult, report: RunReport, prefix: str = "[pbv]") -> str:
    """Subject for a per-VM notification, e.g. ``[pbv] FAIL web01 (105) on restore01``."""
    label = _label(vm.status, cleanup_bad=not vm.cleanup_ok)
    return _join_prefix(prefix, f"{label} {_vm_name(vm)} ({vm.vmid}) on {report.target_node}")


# ── bodies ────────────────────────────────────────────────────────────────────


def _vm_name(vm: VmResult) -> str:
    return vm.name or f"vm{vm.vmid}"


def _duration(seconds: float) -> str:
    s = max(0, round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {s % 3600 // 60:02d}m"


def _parse_iso(ts: str) -> float | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _backup_line(backup: BackupRef | None, reference_ts: str) -> str:
    if backup is None:
        return "  Backup: none"
    parts = []
    ref = _parse_iso(reference_ts)
    if ref is not None and backup.ctime > 0:
        parts.append(f"age {max(0.0, ref - backup.ctime) / 3600:.1f} h")
    parts.append(f"{backup.size / _GIB:.1f} GiB" if backup.size > 0 else "size unknown")
    return f"  Backup: {backup.volid} ({', '.join(parts)})"


def manual_cleanup_line(vm: VmResult, node: str) -> str:
    """The ``MANUAL CLEANUP REQUIRED`` line for a VM whose cleanup failed."""
    return f"MANUAL CLEANUP REQUIRED: VM {vm.temp_vmid} (from {vm.vmid} {_vm_name(vm)}) on {node}"


def sweep_failure_line(entry: str, node: str) -> str:
    """The ``MANUAL CLEANUP REQUIRED`` line for a ``"<temp vmid>: <code> <message>"`` sweep failure."""
    vmid, sep, detail = entry.partition(": ")
    if not sep:
        vmid, detail = "?", entry
    return f"MANUAL CLEANUP REQUIRED: VM {vmid.strip()} on {node} (startup sweep: {detail.strip()})"


def sort_vms(vms: list[VmResult]) -> list[VmResult]:
    """VMs ordered problems first: cleanup failures, then severity desc, then vmid."""
    return sorted(vms, key=lambda v: (v.cleanup_ok, -v.status.rank, v.vmid))


def _step_line(step: StepResult) -> str:
    code = f" {step.error_code}" if step.error_code else ""
    msg = f" — {step.message}" if step.message else ""
    return f"  {_SYMBOL[step.status]} step {step.name}: {step.status.value.upper()}{code}{msg}"


def _vm_block(vm: VmResult, report: RunReport) -> list[str]:
    lines = [
        f"[{vm.status.value.upper()}] {_vm_name(vm)} — vmid {vm.vmid}, temp {vm.temp_vmid}, {_duration(vm.duration_s)}",
        _backup_line(vm.backup, report.started_at),
    ]
    if vm.failure_code or vm.failure_message:
        sep = " — " if vm.failure_code and vm.failure_message else ""
        lines.append(f"  Failure: {vm.failure_code}{sep}{vm.failure_message}")
    # Other failed/degraded steps not already explained by failure_code.
    for step in vm.steps:
        if is_problem(step.status) and not (vm.failure_code and step.error_code == vm.failure_code):
            lines.append(_step_line(step))
    for chk in sorted(vm.checks, key=lambda c: -c.status.rank if is_problem(c.status) else 0):
        summary = f" — {chk.summary}" if chk.summary else ""
        lines.append(f"  {_SYMBOL[chk.status]} {chk.name}{summary}")
    if vm.sanitized:
        lines.append(f"  Sanitize: {len(vm.sanitized)} change(s)")
    if vm.screenshots:
        lines.append(f"  Screenshots: {len(vm.screenshots)}")
    lines.append("  Cleanup: ok" if vm.cleanup_ok else f"  Cleanup: FAILED — temp VM {vm.temp_vmid} may still exist")
    if vm.log_file:
        lines.append(f"  Log: {vm.log_file}")
    return lines


def truncate(text: str, max_chars: int | None) -> str:
    """Cut ``text`` to ``max_chars`` characters, ending with the truncation note."""
    if max_chars is None or len(text) <= max_chars:
        return text
    keep = max(0, max_chars - len(TRUNCATION_NOTE))
    return text[:keep] + TRUNCATION_NOTE


def utf16_len(text: str) -> int:
    """Length in UTF-16 code units (how Telegram counts its 4096 limit)."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def truncate_utf16(text: str, max_units: int) -> str:
    """Like :func:`truncate` but measured in UTF-16 code units.

    Cuts only between code points, so a surrogate pair (e.g. an emoji) is
    never split.
    """
    if utf16_len(text) <= max_units:
        return text
    budget = max(0, max_units - utf16_len(TRUNCATION_NOTE))
    used = cut = 0
    for ch in text:
        used += 2 if ord(ch) > 0xFFFF else 1
        if used > budget:
            break
        cut += 1
    return text[:cut] + TRUNCATION_NOTE


def render_text(report: RunReport, *, max_chars: int | None = None) -> str:
    """Full plain-text body for a run notification (problems first)."""
    bad = cleanup_failed(report)
    label = _label(report.status, interrupted=report.interrupted, cleanup_bad=bad)
    lines = [
        f"pbv run {report.run_id} on {report.target_node}: {label}",
        f"Started:  {report.started_at}",
        f"Finished: {report.finished_at} (duration {_duration(report.duration_s)})",
    ]
    counts = _counts_text(report.counts)
    lines.append(f"VMs: {len(report.vms)}" + (f" ({counts})" if counts else ""))
    if report.interrupted:
        lines.append("Run was INTERRUPTED; remaining VMs were not tested.")

    ordered = sort_vms(report.vms)
    manual = [sweep_failure_line(e, report.target_node) for e in report.sweep_failures]
    manual += [manual_cleanup_line(vm, report.target_node) for vm in ordered if not vm.cleanup_ok]
    if manual:
        lines += ["", *manual]

    failed_preflight = [s for s in report.preflight if is_problem(s.status)]
    if failed_preflight:
        lines += ["", "Preflight:", *(_step_line(s) for s in failed_preflight)]

    for vm in ordered:
        lines += ["", *_vm_block(vm, report)]

    if report.notify_errors:
        lines += ["", "Notification errors:", *(f"  - {e}" for e in report.notify_errors)]
    if report.leftovers_swept:
        lines += ["", "Leftovers swept: " + ", ".join(str(v) for v in report.leftovers_swept)]
    return truncate("\n".join(lines) + "\n", max_chars)


def render_vm_text(vm: VmResult, report: RunReport) -> str:
    """Plain-text body for a per-VM notification."""
    label = _label(vm.status, cleanup_bad=not vm.cleanup_ok)
    lines = [f"pbv run {report.run_id} on {report.target_node}: VM {_vm_name(vm)} ({vm.vmid}) {label}"]
    if not vm.cleanup_ok:
        lines.append(manual_cleanup_line(vm, report.target_node))
    lines += ["", *_vm_block(vm, report)]
    return "\n".join(lines) + "\n"
