"""Small urllib helper shared by the ntfy and Telegram notifiers.

Retries HTTP 429/5xx responses and failures that happened before the request
was sent (connection refused, temporary DNS failure, unreachable network)
with an injected ``sleep``. Timeouts and resets are never retried: the server
may already have accepted the message, and a retry would duplicate it. Any
non-2xx final status fails; redirects are refused for every method but
GET/HEAD so a POST is never silently turned into a body-less GET.
Error messages contain the status,
reason and at most 200 characters of the response, never the URL (Telegram
URLs contain the bot token) and never a configured secret.
"""

from __future__ import annotations

import errno
import json
import logging
import socket
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


# Errnos that mean the request never left this host (safe to resend).
_PRE_SEND_ERRNOS = frozenset({errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH})


class NoUnsafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects for GET/HEAD only; any other method gets the 3xx as an error.

    urllib's default handler re-issues a redirected POST as a body-less GET,
    which ntfy answers with 200 (its web app), so the message would be lost
    while the notifier reports success.
    """

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        if req.get_method() not in ("GET", "HEAD"):
            return None  # urllib then raises HTTPError(code)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(*handlers: urllib.request.BaseHandler) -> Opener:
    """An :data:`Opener` that refuses redirects of non-GET requests."""
    op = urllib.request.build_opener(NoUnsafeRedirectHandler(), *handlers)
    return lambda req, timeout: op.open(req, timeout=timeout)


def default_opener() -> Opener:
    """An opener honouring the environment's proxy settings."""
    return build_opener()


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
        body = resp.read(4096) if not 200 <= status < 300 else b""
    finally:
        close = getattr(resp, "close", None)
        if close is not None:
            close()
    return int(status), str(reason), body


def _root_cause(exc: BaseException) -> object:
    return exc.reason if isinstance(exc, urllib.error.URLError) else exc


def _failed_before_send(exc: BaseException) -> bool:
    """True if ``exc`` proves the request was never sent (so resending is safe)."""
    reason = _root_cause(exc)
    if isinstance(reason, socket.gaierror):
        return reason.errno == socket.EAI_AGAIN
    if isinstance(reason, ConnectionRefusedError):
        return True
    return isinstance(reason, OSError) and reason.errno in _PRE_SEND_ERRNOS


def _connection_reason(exc: BaseException) -> str:
    reason = _root_cause(exc)
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
    """Perform ``req``; retry safe transient failures, raise ``NOTIFY_FAIL`` otherwise."""
    secrets = tuple(secrets)
    attempt = 0
    while True:
        try:
            status, reason, body = _open(opener, req, timeout)
        except (urllib.error.URLError, OSError) as exc:
            error: PbvError = notify_error(label, f"connection failed ({_connection_reason(exc)})", secrets)
            transient = _failed_before_send(exc)
        else:
            if 200 <= status < 300:
                return
            if 300 <= status < 400:
                detail = f"HTTP {status} redirect refused; check server URL"
            else:
                snippet = _snippet(body)
                detail = f"HTTP {status} {reason}".rstrip() + (f": {snippet}" if snippet else "")
            error = notify_error(label, detail, secrets)
            transient = status == 429 or status >= 500
        if not transient or attempt >= len(delays):
            raise error
        log.warning("NOTIFY_RETRY notifier=%s attempt=%d reason=%s", label, attempt + 1, scrub(str(error), secrets))
        sleep(delays[attempt])
        attempt += 1
