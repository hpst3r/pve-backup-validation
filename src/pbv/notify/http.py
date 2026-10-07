"""Small urllib helper shared by the ntfy and Telegram notifiers.

Retries HTTP 429/5xx and connection failures with an injected ``sleep``;
any other HTTP error fails immediately. Error messages contain the status,
reason and at most 200 characters of the response, never the URL (Telegram
URLs contain the bot token) and never a configured secret.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from pbv.core import PbvError
from pbv.notify.base import notify_error, scrub

log = logging.getLogger("pbv.notify")

Opener = Callable[[urllib.request.Request, float], Any]
"""``opener(request, timeout) -> response``; may raise ``urllib.error.HTTPError``."""

RETRY_DELAYS: tuple[float, ...] = (1.0, 3.0)
MAX_SNIPPET = 200


def default_opener() -> Opener:
    """An opener honouring the environment's proxy settings."""
    op = urllib.request.build_opener()
    return lambda req, timeout: op.open(req, timeout=timeout)


def _snippet(body: bytes) -> str:
    text = body.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        # Telegram: {"description": ...}; ntfy: {"error": ...}
        for key in ("description", "error", "message"):
            if isinstance(doc.get(key), str):
                text = doc[key]
                break
    text = " ".join(text.split())
    return text[:MAX_SNIPPET]


def _open(opener: Opener, req: urllib.request.Request, timeout: float) -> tuple[int, str, bytes]:
    try:
        resp = opener(req, timeout)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(4096) or b""
        except OSError:
            body = b""
        finally:
            exc.close()
        return exc.code, str(exc.reason or ""), body
    try:
        status = getattr(resp, "status", None) or resp.getcode()
        reason = getattr(resp, "reason", "") or ""
        body = resp.read(4096) if status >= 400 else b""
    finally:
        close = getattr(resp, "close", None)
        if close is not None:
            close()
    return int(status), str(reason), body


def _connection_reason(exc: BaseException) -> str:
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, OSError) and reason.strerror:
        return f"{type(reason).__name__}: {reason.strerror}"
    if isinstance(reason, BaseException):
        return type(reason).__name__ + (f": {reason}" if str(reason) else "")
    return str(reason)


def send(
    opener: Opener,
    req: urllib.request.Request,
    *,
    label: str,
    timeout: float,
    sleep: Callable[[float], None],
    secrets: Iterable[str] = (),
    delays: Sequence[float] = RETRY_DELAYS,
) -> None:
    """Perform ``req``; retry transient failures, raise ``NOTIFY_FAIL`` otherwise."""
    secrets = tuple(secrets)
    attempt = 0
    while True:
        try:
            status, reason, body = _open(opener, req, timeout)
        except (urllib.error.URLError, OSError) as exc:
            error: PbvError = notify_error(label, f"connection failed ({_connection_reason(exc)})", secrets)
            transient = True
        else:
            if status < 400:
                return
            snippet = _snippet(body)
            error = notify_error(
                label, f"HTTP {status} {reason}".rstrip() + (f": {snippet}" if snippet else ""), secrets
            )
            transient = status == 429 or status >= 500
        if not transient or attempt >= len(delays):
            raise error
        log.warning("NOTIFY_RETRY notifier=%s attempt=%d reason=%s", label, attempt + 1, scrub(str(error), secrets))
        sleep(delays[attempt])
        attempt += 1
