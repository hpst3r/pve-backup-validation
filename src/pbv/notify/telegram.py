"""Telegram notifier: plain-text ``sendMessage`` (legacy parity, no parse_mode)."""

from __future__ import annotations

import time
import urllib.parse
import urllib.request
from collections.abc import Callable

from pbv.config import TelegramConfig
from pbv.core import RunReport, VmResult
from pbv.notify import http
from pbv.notify.base import BaseNotifier
from pbv.notify.render import render_text, render_vm_text, run_needs_attention, truncate_utf16, vm_needs_attention

API_BASE = "https://api.telegram.org"
MAX_CHARS = 4096  # Telegram counts UTF-16 code units, not code points


class TelegramNotifier(BaseNotifier):
    """Sends the rendered text to a chat (optionally a forum topic).

    The request URL embeds the bot token, so it never appears in errors or
    logs; ``api_base`` is injectable for tests.
    """

    name = "telegram"

    def __init__(
        self,
        cfg: TelegramConfig,
        *,
        opener: http.Opener | None = None,
        sleep: Callable[[float], None] = time.sleep,
        api_base: str = API_BASE,
    ) -> None:
        self.cfg = cfg
        self.when = cfg.when
        self.per_vm = cfg.per_vm
        self._secrets = (cfg.token,) if cfg.token else ()
        self._opener = opener or http.default_opener()
        self._sleep = sleep
        self._api_base = api_base.rstrip("/")

    def __repr__(self) -> str:
        return f"TelegramNotifier(chat_id={self.cfg.chat_id!r})"

    def _send_run(self, report: RunReport) -> None:
        self._send_message(truncate_utf16(render_text(report), MAX_CHARS), quiet=not run_needs_attention(report))

    def _send_vm(self, result: VmResult, report: RunReport) -> None:
        self._send_message(
            truncate_utf16(render_vm_text(result, report), MAX_CHARS), quiet=not vm_needs_attention(result)
        )

    def _send_message(self, text: str, *, quiet: bool) -> None:
        form = {"chat_id": self.cfg.chat_id, "text": text}
        if self.cfg.thread_id:
            form["message_thread_id"] = self.cfg.thread_id
        if quiet:
            form["disable_notification"] = "true"
        req = urllib.request.Request(  # noqa: S310
            f"{self._api_base}/bot{self.cfg.token}/sendMessage",
            data=urllib.parse.urlencode(form).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        http.send(
            self._opener,
            req,
            label=self.name,
            timeout=self.cfg.timeout_s,
            sleep=self._sleep,
            secrets=self._secrets,
        )
