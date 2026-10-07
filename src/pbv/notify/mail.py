"""Email notifier over ``smtplib`` (STARTTLS, implicit SSL or plain)."""

from __future__ import annotations

import contextlib
import smtplib
import ssl
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Any

from pbv.config import EmailConfig
from pbv.core import RunReport, VmResult
from pbv.notify.base import BaseNotifier, notify_error, report_screenshots, select_attachments
from pbv.notify.render import render_subject, render_text, render_vm_subject, render_vm_text

MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024

SmtpFactory = Callable[[str, int, float], Any]
"""``smtp_factory(host, port, timeout) -> smtplib.SMTP``-like object."""


class EmailNotifier(BaseNotifier):
    """Sends ``text/plain`` UTF-8 mail with optional PNG screenshots attached.

    ``smtp_factory`` is injectable; by default it is ``smtplib.SMTP`` (or
    ``SMTP_SSL`` with a default TLS context when ``security == "ssl"``).
    """

    name = "email"

    def __init__(self, cfg: EmailConfig, *, smtp_factory: SmtpFactory | None = None) -> None:
        self.cfg = cfg
        self.when = cfg.when
        self.per_vm = cfg.per_vm
        self._secrets = (cfg.password,) if cfg.password else ()
        self._factory = smtp_factory or self._default_factory

    def __repr__(self) -> str:
        return f"EmailNotifier(smtp_host={self.cfg.smtp_host!r}, to={self.cfg.to!r})"

    def _default_factory(self, host: str, port: int, timeout: float) -> smtplib.SMTP:
        if self.cfg.security == "ssl":
            return smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
        return smtplib.SMTP(host, port, timeout=timeout)

    def _send_run(self, report: RunReport) -> None:
        shots = report_screenshots(report) if self.cfg.attach_screenshots else []
        self._deliver(self.build_message(render_subject(report, self.cfg.subject_prefix), render_text(report), shots))

    def _send_vm(self, result: VmResult, report: RunReport) -> None:
        shots = list(result.screenshots) if self.cfg.attach_screenshots else []
        subject = render_vm_subject(result, report, self.cfg.subject_prefix)
        self._deliver(self.build_message(subject, render_vm_text(result, report), shots))

    def build_message(self, subject: str, body: str, screenshots: Sequence[str] = ()) -> EmailMessage:
        """Assemble the message; screenshots beyond the limits are noted in the body."""
        files, skipped = select_attachments(screenshots, max_files=MAX_ATTACHMENTS, max_bytes=MAX_ATTACHMENT_BYTES)
        if skipped:
            body += f"\n{skipped} screenshot(s) not attached (limit {MAX_ATTACHMENTS} files / 10 MiB, PNG only).\n"
        msg = EmailMessage()
        msg["From"] = self.cfg.sender
        msg["To"] = ", ".join(self.cfg.to)
        msg["Subject"] = subject
        msg["Date"] = format_datetime(datetime.now(UTC))
        domain = self.cfg.sender.rpartition("@")[2] or "pbv.invalid"
        msg["Message-ID"] = make_msgid(idstring="pbv", domain=domain)
        msg.set_content(body, charset="utf-8")
        for filename, data in files:
            msg.add_attachment(data, maintype="image", subtype="png", filename=filename)
        return msg

    def _deliver(self, msg: EmailMessage) -> None:
        host, port = self.cfg.smtp_host, self.cfg.smtp_port
        try:
            smtp = self._factory(host, port, self.cfg.timeout_s)
        except (OSError, smtplib.SMTPException) as exc:
            raise notify_error(
                self.name, f"cannot connect to {host}:{port} ({_describe(exc)})", self._secrets
            ) from None
        try:
            if self.cfg.security == "starttls":
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if self.cfg.username:
                smtp.login(self.cfg.username, self.cfg.password)
            smtp.send_message(msg)
        except (OSError, smtplib.SMTPException) as exc:
            raise notify_error(self.name, _describe(exc), self._secrets) from None
        finally:
            with contextlib.suppress(OSError, smtplib.SMTPException):
                smtp.quit()


def _describe(exc: BaseException) -> str:
    """``SMTPAuthenticationError (535)`` / ``ConnectionRefusedError: ...`` — no server text."""
    name = type(exc).__name__
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"{name} ({exc.smtp_code})"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        codes = sorted({str(code) for code, _msg in exc.recipients.values()})
        return f"{name} ({', '.join(codes)})"
    if isinstance(exc, ssl.SSLError) and getattr(exc, "reason", None):
        return f"{name}: {exc.reason}"
    if isinstance(exc, OSError) and exc.strerror:
        return f"{name}: {exc.strerror}"
    return name
