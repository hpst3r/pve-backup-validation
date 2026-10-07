"""Fixtures: a TLS loopback PVE stand-in with a route table that records requests."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from pbv.pve import PveClient

SECRET = "SENTINEL-SECRET-0f3c2a"
TOKEN_ID = "pbv@pve!validate"
DROP = object()  # route result: close the connection without responding


@dataclass
class Req:
    method: str
    raw_path: str  # path + query exactly as sent (still quoted)
    path: str  # unquoted path without query
    headers: dict[str, str]
    query: dict[str, list[str]]
    form: dict[str, list[str]]
    body: bytes


@dataclass
class Reply:
    status: int = 200
    body: Any = None  # dict → JSON; bytes → raw
    reason: str | None = None
    delay_s: float = 0.0


Handler = Callable[[Req], "Reply | dict[str, Any] | object"]


@dataclass
class Server:
    port: int
    cert_file: Path
    fingerprint: str
    routes: list[tuple[str, re.Pattern[str], Handler]] = field(default_factory=list)
    requests: list[Req] = field(default_factory=list)

    def route(self, method: str, path_regex: str, handler: Handler | Reply | dict[str, Any]) -> None:
        """Register a handler; static replies/dicts are wrapped. Later routes win."""
        if not callable(handler):
            static = handler
            handler = lambda req: static  # noqa: E731
        self.routes.insert(0, (method, re.compile(f"^{path_regex}$"), handler))

    def reqs(self, method: str | None = None, path_contains: str = "") -> list[Req]:
        return [r for r in self.requests if (method is None or r.method == method) and path_contains in r.path]

    def client(self, **kw: Any) -> PveClient:
        args: dict[str, Any] = {
            "port": self.port,
            "fingerprint": self.fingerprint,
            "timeout_s": 2,
            "retries": 3,
            "sleep": lambda s: None,
        }
        args.update(kw)
        return PveClient("127.0.0.1", "restore01", TOKEN_ID, SECRET, **args)


def _make_handler(server: Server) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            pass

        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            split = urlsplit(self.path)
            ctype = self.headers.get("Content-Type", "")
            req = Req(
                method=self.command,
                raw_path=self.path,
                path=unquote(split.path),
                headers={k: v for k, v in self.headers.items()},
                query=parse_qs(split.query, keep_blank_values=True),
                form=parse_qs(body.decode(), keep_blank_values=True)
                if ctype.startswith("application/x-www-form-urlencoded")
                else {},
                body=body,
            )
            server.requests.append(req)
            path = req.path.removeprefix("/api2/json")
            result: Any = Reply(404, {"data": None, "message": f"no route {self.command} {path}"}, "Not Found")
            for method, rx, handler in server.routes:
                if method == self.command and rx.match(path):
                    result = handler(req)
                    break
            if result is DROP:
                self.close_connection = True
                return
            if not isinstance(result, Reply):
                result = Reply(200, result)
            if result.delay_s:
                time.sleep(result.delay_s)
            payload = result.body if isinstance(result.body, bytes) else json.dumps(result.body).encode()
            self.send_response(result.status, result.reason)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        do_GET = do_POST = do_PUT = do_DELETE = _serve

    return H


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # clients that time out or hang up mid-response are part of the tests


@pytest.fixture(scope="session")
def tls_cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert, key


@pytest.fixture(scope="session")
def _tls_server(tls_cert: tuple[Path, Path]) -> Iterator[Server]:
    cert, key = tls_cert
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    srv = Server(port=0, cert_file=cert, fingerprint=hashlib.sha256(der).hexdigest())
    httpd = _QuietServer(("127.0.0.1", 0), _make_handler(srv))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    srv.port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield srv
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def srv(_tls_server: Server) -> Server:
    """The shared TLS server with routes and recorded requests reset."""
    _tls_server.routes.clear()
    _tls_server.requests.clear()
    return _tls_server


@pytest.fixture
def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeClock:
    """Monotonic clock advanced only by its own ``sleep``."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
