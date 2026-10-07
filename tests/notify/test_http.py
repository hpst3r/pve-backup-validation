"""Retry policy, redirect refusal and status handling of the shared HTTP helper."""

from __future__ import annotations

import errno
import http.client
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from pbv.core import PbvError
from pbv.notify import http as notify_http

from .conftest import HttpRecorder


def _req(url: str = "http://127.0.0.1:9/topic", method: str = "POST") -> urllib.request.Request:
    return urllib.request.Request(url, data=b"msg", method=method)  # noqa: S310


def _send(opener: notify_http.Opener, sleeps: list[float], req: urllib.request.Request | None = None) -> None:
    notify_http.send(opener, req or _req(), label="ntfy", timeout=0.3, sleep=sleeps.append)


def _raising(exc: BaseException, calls: list[int]) -> notify_http.Opener:
    def opener(req: Any, timeout: float) -> Any:
        calls.append(1)
        raise exc

    return opener


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")),
        urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")),
        urllib.error.URLError(OSError(errno.ENETUNREACH, "Network is unreachable")),
        urllib.error.URLError(OSError(errno.EHOSTUNREACH, "No route to host")),
        ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
    ],
    ids=["refused", "eai_again", "netunreach", "hostunreach", "bare-refused"],
)
def test_pre_send_failures_are_retried(exc: BaseException) -> None:
    calls: list[int] = []
    sleeps: list[float] = []
    with pytest.raises(PbvError, match=r"^ntfy: connection failed") as ei:
        _send(_raising(exc, calls), sleeps)
    assert ei.value.code == "NOTIFY_FAIL"
    assert len(calls) == 3 and sleeps == [1.0, 3.0]


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError(TimeoutError("timed out")),
        TimeoutError("timed out"),
        urllib.error.URLError(ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")),
        ConnectionResetError(errno.ECONNRESET, "Connection reset by peer"),
        http.client.RemoteDisconnected("Remote end closed connection without response"),
        urllib.error.URLError(BrokenPipeError(errno.EPIPE, "Broken pipe")),
        urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "Name or service not known")),
        urllib.error.URLError("unknown url type"),
    ],
    ids=["timeout", "bare-timeout", "reset", "bare-reset", "disconnected", "epipe", "eai_noname", "str-reason"],
)
def test_possibly_sent_or_permanent_failures_are_not_retried(exc: BaseException) -> None:
    calls: list[int] = []
    sleeps: list[float] = []
    with pytest.raises(PbvError, match=r"^ntfy: connection failed") as ei:
        _send(_raising(exc, calls), sleeps)
    assert ei.value.code == "NOTIFY_FAIL"
    assert len(calls) == 1 and sleeps == []


@pytest.fixture
def silent_server() -> Iterator[tuple[str, list[bytes]]]:
    """Accepts and reads a request, then never answers (provokes a read timeout)."""
    received: list[bytes] = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    stop = threading.Event()
    conns: list[socket.socket] = []

    def serve() -> None:
        srv.settimeout(0.05)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            conns.append(conn)
            received.append(conn.recv(65536))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.getsockname()[1]}", received
    finally:
        stop.set()
        t.join(1)
        for c in conns:
            c.close()
        srv.close()


def test_read_timeout_after_send_is_not_retried(silent_server: tuple[str, list[bytes]]) -> None:
    url, received = silent_server
    sleeps: list[float] = []
    opener = notify_http.build_opener(urllib.request.ProxyHandler({}))
    with pytest.raises(PbvError, match=r"^ntfy: connection failed"):
        _send(opener, sleeps, _req(url + "/topic"))
    assert len(received) == 1 and received[0].startswith(b"POST /topic")
    assert sleeps == []  # a retry could publish the message twice


def test_connection_refused_on_real_socket_is_retried() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here now
    sleeps: list[float] = []
    opener = notify_http.build_opener(urllib.request.ProxyHandler({}))
    with pytest.raises(PbvError, match=r"ConnectionRefusedError"):
        _send(opener, sleeps, _req(f"http://127.0.0.1:{port}/topic"))
    assert sleeps == [1.0, 3.0]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_post_redirect_refused_and_not_followed(http_server: HttpRecorder, status: int) -> None:
    http_server.responses = [(status, b"", {"Location": "/moved/topic"})]
    sleeps: list[float] = []
    with pytest.raises(PbvError) as ei:
        _send(http_server.opener(), sleeps, _req(http_server.url + "/topic"))
    assert str(ei.value) == f"ntfy: HTTP {status} redirect refused; check server URL"
    assert ei.value.code == "NOTIFY_FAIL"
    assert [(r.method, r.path) for r in http_server.requests] == [("POST", "/topic")]
    assert sleeps == []


def test_put_redirect_refused(http_server: HttpRecorder) -> None:
    http_server.responses = [(307, b"", {"Location": "/moved/topic"})]
    with pytest.raises(PbvError, match=r"^ntfy: HTTP 307 redirect refused"):
        _send(http_server.opener(), [], _req(http_server.url + "/topic", method="PUT"))
    assert [r.method for r in http_server.requests] == ["PUT"]


def test_get_redirect_still_followed(http_server: HttpRecorder) -> None:
    http_server.responses = [(302, b"", {"Location": "/moved"})]
    req = urllib.request.Request(http_server.url + "/start")  # noqa: S310
    _send(http_server.opener(), [], req)
    assert [(r.method, r.path) for r in http_server.requests] == [("GET", "/start"), ("GET", "/moved")]


class _Resp:
    def __init__(self, status: int) -> None:
        self.status = status
        self.reason = "Whatever"

    def read(self, n: int = -1) -> bytes:
        return b""

    def close(self) -> None:
        pass


@pytest.mark.parametrize("status", [100, 204, 304, 399])
def test_only_2xx_counts_as_success(status: int) -> None:
    def opener(req: Any, timeout: float) -> Any:
        return _Resp(status)

    if 200 <= status < 300:
        _send(opener, [])
        return
    with pytest.raises(PbvError) as ei:
        _send(opener, [])
    assert ei.value.code == "NOTIFY_FAIL"
    if 300 <= status < 400:
        assert str(ei.value) == f"ntfy: HTTP {status} redirect refused; check server URL"


def test_redirect_handler_only_blocks_unsafe_methods() -> None:
    h = notify_http.NoUnsafeRedirectHandler()
    for method in ("POST", "PUT", "DELETE"):
        assert h.redirect_request(_req(method=method), None, 301, "Moved", {}, "http://x/y") is None
    new = h.redirect_request(_req(method="GET"), None, 301, "Moved", {}, "http://x/y")
    assert new is not None and new.full_url == "http://x/y"
