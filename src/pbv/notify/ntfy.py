"""ntfy notifier: ``POST {server}/{topic}`` plus optional PNG uploads via ``PUT``."""

from __future__ import annotations

import base64
import time
import urllib.request
from collections.abc import Callable

from pbv.config import NtfyConfig
from pbv.core import RunReport, VmResult
from pbv.notify import http
from pbv.notify.base import BaseNotifier, report_screenshots, select_attachments
from pbv.notify.render import (
    TRUNCATION_NOTE,
    render_subject,
    render_text,
    render_vm_subject,
    render_vm_text,
    run_needs_attention,
    vm_needs_attention,
)

MAX_BODY_BYTES = 4096
MAX_ATTACHMENTS = 3
MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024  # ntfy.sh default attachment limit


def encode_header(value: str) -> str:
    """Return ``value`` unchanged if ASCII, else as RFC 2047 ``=?UTF-8?B?...?=``."""
    if value.isascii():
        return value
    return "=?UTF-8?B?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="


def truncate_bytes(text: str, limit: int = MAX_BODY_BYTES) -> bytes:
    """UTF-8 encode ``text``; if longer than ``limit`` bytes cut it and append the note."""
    data = text.encode("utf-8")
    if len(data) <= limit:
        return data
    note = TRUNCATION_NOTE.encode("utf-8")
    head = data[: max(0, limit - len(note))].decode("utf-8", "ignore").encode("utf-8")
    return head + note


class NtfyNotifier(BaseNotifier):
    """Publishes the rendered text to an ntfy topic.

    ``opener(request, timeout)`` is injectable (default: urllib with proxy
    support); ``sleep`` is used for the 429/5xx retry backoff.
    """

    name = "ntfy"

    def __init__(
        self,
        cfg: NtfyConfig,
        *,
        opener: http.Opener | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cfg = cfg
        self.when = cfg.when
        self.per_vm = cfg.per_vm
        self._secrets = (cfg.token,) if cfg.token else ()
        self._opener = opener or http.default_opener()
        self._sleep = sleep
        self._url = f"{cfg.server.rstrip('/')}/{cfg.topic}"

    def __repr__(self) -> str:
        return f"NtfyNotifier(server={self.cfg.server!r}, topic={self.cfg.topic!r})"

    def _send_run(self, report: RunReport) -> None:
        shots = report_screenshots(report) if self.cfg.attach_screenshots else []
        self._publish(render_subject(report), render_text(report), run_needs_attention(report), shots)

    def _send_vm(self, result: VmResult, report: RunReport) -> None:
        shots = list(result.screenshots) if self.cfg.attach_screenshots else []
        self._publish(
            render_vm_subject(result, report), render_vm_text(result, report), vm_needs_attention(result), shots
        )

    def _headers(self, title: str, bad: bool) -> dict[str, str]:
        tags = self.cfg.tags_fail if bad else self.cfg.tags_ok
        headers = {
            "Title": encode_header(title),
            "Priority": self.cfg.priority_fail if bad else self.cfg.priority_ok,
        }
        if tags:
            headers["Tags"] = ",".join(tags)
        if self.cfg.click_url:
            headers["Click"] = self.cfg.click_url
        if self.cfg.token:
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        return headers

    def _publish(self, title: str, text: str, bad: bool, screenshots: list[str]) -> None:
        headers = self._headers(title, bad)
        headers["Content-Type"] = "text/plain; charset=utf-8"
        req = urllib.request.Request(self._url, data=truncate_bytes(text), headers=headers, method="POST")  # noqa: S310
        self._send(req)
        files, _skipped = select_attachments(screenshots, max_files=MAX_ATTACHMENTS, max_bytes=MAX_ATTACHMENT_BYTES)
        for filename, data in files:
            att_headers = self._headers(title, bad)
            att_headers["Filename"] = encode_header(filename)
            req = urllib.request.Request(self._url, data=data, headers=att_headers, method="PUT")  # noqa: S310
            self._send(req)

    def _send(self, req: urllib.request.Request) -> None:
        http.send(
            self._opener,
            req,
            label=self.name,
            timeout=self.cfg.timeout_s,
            sleep=self._sleep,
            secrets=self._secrets,
        )
