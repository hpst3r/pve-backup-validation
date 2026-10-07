"""pbv.notify — rendering and notification sinks (SPEC §6).

``build_notifiers`` turns :class:`pbv.config.NotifyConfig` into a list of
:class:`pbv.core.Notifier` objects (email, ntfy, telegram, then JSON last so
the written report includes the other notifiers' errors). Each notifier does
its own ``when``/``per_vm`` gating and raises only
``PbvError(code="NOTIFY_FAIL")`` with a secret-free message.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from pbv.config import NotifyConfig
from pbv.core import BackupRef, Notifier, PbvError, RunReport, Status, StepResult, VmResult, utc_now_iso
from pbv.notify.base import BaseNotifier
from pbv.notify.http import Opener
from pbv.notify.jsonfile import JsonNotifier
from pbv.notify.mail import EmailNotifier, SmtpFactory
from pbv.notify.ntfy import NtfyNotifier
from pbv.notify.render import (
    render_subject,
    render_text,
    render_vm_subject,
    render_vm_text,
    should_send,
)
from pbv.notify.telegram import TelegramNotifier

__all__ = [
    "EmailNotifier",
    "JsonNotifier",
    "NtfyNotifier",
    "TelegramNotifier",
    "build_notifiers",
    "render_subject",
    "render_text",
    "render_vm_subject",
    "render_vm_text",
    "send_test",
    "should_send",
    "synthetic_report",
]

log = logging.getLogger("pbv.notify")


def build_notifiers(
    cfg: NotifyConfig,
    *,
    run_dir: Path | None = None,
    smtp_factory: SmtpFactory | None = None,
    opener: Opener | None = None,
    sleep: Callable[[float], None] = time.sleep,
    stdout: TextIO | None = None,
) -> list[Notifier]:
    """Instantiate every enabled notifier.

    ``run_dir`` is accepted for wiring symmetry and currently unused (the JSON
    directory comes from ``cfg.json.dir``). ``stdout=None`` means
    ``sys.stdout`` at write time.
    """
    del run_dir
    out: list[Notifier] = []
    if cfg.email.enabled:
        out.append(EmailNotifier(cfg.email, smtp_factory=smtp_factory))
    if cfg.ntfy.enabled:
        out.append(NtfyNotifier(cfg.ntfy, opener=opener, sleep=sleep))
    if cfg.telegram.enabled:
        out.append(TelegramNotifier(cfg.telegram, opener=opener, sleep=sleep))
    if cfg.json.enabled:
        out.append(JsonNotifier(cfg.json, stdout=stdout))
    return out


def synthetic_report(node: str = "test") -> RunReport:
    """A one-VM PASS report used by :func:`send_test` (``pbv notify-test``)."""
    now = utc_now_iso()
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-test"
    vm = VmResult(
        vmid=100,
        temp_vmid=900100,
        name="pbv-notify-test",
        status=Status.PASS,
        started_at=now,
        duration_s=0.0,
        backup=BackupRef(volid="pbs:backup/vm/100/test", vmid=100, ctime=int(time.time()), size=0),
        steps=[StepResult(name="notify-test", status=Status.PASS, started_at=now, duration_s=0.0)],
    )
    return RunReport(
        run_id=run_id,
        target_node=node,
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        status=Status.PASS,
        vms=[vm],
    )


def send_test(notifiers: Sequence[Notifier], *, node: str = "test") -> dict[str, str]:
    """Send a synthetic PASS report through every notifier, ignoring ``when``.

    Returns ``{notifier.name: "ok" | "<error message>"}``. The JSON notifier
    writes only ``<run_id>.json`` (run_id ends in ``-test``), never
    ``latest.json``.
    """
    report = synthetic_report(node)
    results: dict[str, str] = {}
    for notifier in notifiers:
        try:
            if isinstance(notifier, BaseNotifier):
                notifier.run_finished(report, force=True)
            else:
                notifier.run_finished(report)
        except PbvError as exc:
            results[notifier.name] = str(exc)
        except Exception as exc:  # boundary: report, never crash notify-test
            log.debug("notify-test %s failed", notifier.name, exc_info=True)
            results[notifier.name] = f"{notifier.name}: unexpected {type(exc).__name__}"
        else:
            results[notifier.name] = "ok"
    return results
