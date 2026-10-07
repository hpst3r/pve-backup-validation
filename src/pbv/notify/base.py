"""Shared notifier plumbing: gating, error boundary, secret scrubbing, attachments."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from pbv.core import NotifyWhen, PbvError, RunReport, VmResult
from pbv.notify.render import should_send_run, should_send_vm, sort_vms

log = logging.getLogger("pbv.notify")

NOTIFY_FAIL = "NOTIFY_FAIL"
REDACTED = "***"


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Replace every non-empty secret in ``text`` with ``***``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def notify_error(name: str, message: str, secrets: Iterable[str] = ()) -> PbvError:
    """Build the ``NOTIFY_FAIL`` error every notifier raises (secret-free)."""
    return PbvError(scrub(f"{name}: {message}", secrets), code=NOTIFY_FAIL)


class BaseNotifier:
    """Implements the ``when``/``per_vm`` gating and the exception boundary.

    Subclasses set ``name``, ``when``, ``per_vm`` and ``_secrets`` and implement
    :meth:`_send_run` / :meth:`_send_vm`. Any exception escaping those is
    converted to ``PbvError(code="NOTIFY_FAIL")`` with a secret-free message.
    """

    name: str = "notifier"
    when: NotifyWhen = NotifyWhen.FAILURE
    per_vm: bool = False
    _secrets: tuple[str, ...] = ()

    def vm_finished(self, result: VmResult, report: RunReport) -> None:
        if self.per_vm and should_send_vm(self.when, result):
            self._guard(self._send_vm, result, report)

    def run_finished(self, report: RunReport, *, force: bool = False) -> None:
        """Send the run summary; ``force`` bypasses ``when`` (used by ``send_test``)."""
        if force or should_send_run(self.when, report):
            self._guard(self._send_run, report)

    def _send_run(self, report: RunReport) -> None:
        raise NotImplementedError

    def _send_vm(self, result: VmResult, report: RunReport) -> None:
        raise NotImplementedError

    def _guard(self, fn: Callable[..., None], *args: object) -> None:
        try:
            fn(*args)
        except PbvError as exc:
            if exc.code != NOTIFY_FAIL:
                raise notify_error(self.name, f"{exc.code} {exc}", self._secrets) from None
            raise
        except Exception as exc:  # boundary: a notifier must never crash the run
            log.debug(
                "%s notifier failed:\n%s", self.name, scrub("".join(traceback.format_exception(exc)), self._secrets)
            )
            raise notify_error(self.name, f"unexpected {type(exc).__name__}", self._secrets) from None
        log.info("NOTIFY_OK notifier=%s", self.name)


def report_screenshots(report: RunReport) -> list[str]:
    """Screenshots of all VMs, problem VMs first."""
    return [shot for vm in sort_vms(report.vms) for shot in vm.screenshots]


def select_attachments(paths: Sequence[str], *, max_files: int, max_bytes: int) -> tuple[list[tuple[str, bytes]], int]:
    """Read PNGs in order within the limits; return ``([(filename, data)], skipped)``.

    Non-PNG, unreadable, or over-limit files are skipped and counted.
    """
    chosen: list[tuple[str, bytes]] = []
    total = 0
    skipped = 0
    for raw in paths:
        path = Path(raw)
        if len(chosen) >= max_files or path.suffix.lower() != ".png":
            skipped += 1
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            log.warning("ATTACH_SKIP file=%s reason=%s", path, exc.strerror or type(exc).__name__)
            skipped += 1
            continue
        if total + len(data) > max_bytes:
            skipped += 1
            continue
        chosen.append((path.name, data))
        total += len(data)
    return chosen, skipped
