"""Shared fixtures for pbv.notify tests: report builders and loopback servers."""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

from pbv.core import BackupRef, CheckResult, RunReport, Status, StepResult, VmResult
from pbv.notify import http as notify_http

T0 = "2026-10-07T02:00:00Z"
T0_EPOCH = int(datetime(2026, 10, 7, 2, 0, 0, tzinfo=UTC).timestamp())
GIB = 1024**3
SECRET = "SENTINEL-s3cr3t-T0KEN-9f8e7d"

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def make_vm(vmid: int, status: Status = Status.PASS, **kw: Any) -> VmResult:
    defaults: dict[str, Any] = {
        "temp_vmid": 900000 + vmid,
        "name": f"vm{vmid}",
        "started_at": T0,
        "duration_s": 81.0,
        "backup": BackupRef(
            volid=f"pbs:backup/vm/{vmid}/2026-10-06T02:00:00Z",
            vmid=vmid,
            ctime=T0_EPOCH - 24 * 3600,
            size=int(12.3 * GIB),
        ),
    }
    defaults.update(kw)
    return VmResult(vmid=vmid, status=status, **defaults)


def make_report(vms: list[VmResult], status: Status | None = None, **kw: Any) -> RunReport:
    defaults: dict[str, Any] = {
        "run_id": "20261007T020000Z-ab12",
        "target_node": "restore01",
        "started_at": T0,
        "finished_at": "2026-10-07T02:10:00Z",
        "duration_s": 600.0,
    }
    defaults.update(kw)
    return RunReport(vms=vms, status=status or Status.worst([v.status for v in vms], Status.PASS), **defaults)


def check(name: str, status: Status, summary: str = "") -> CheckResult:
    return CheckResult(name=name, type=name.split(":")[0], status=status, summary=summary)


def step(name: str, status: Status, code: str = "", message: str = "") -> StepResult:
    return StepResult(name=name, status=status, started_at=T0, duration_s=1.0, message=message, error_code=code)


# ── loopback HTTP server ──────────────────────────────────────────────────────


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HttpRecorder:
    """A loopback HTTP server recording requests and replaying canned responses."""

    url: str = ""
    requests: list[Recorded] = field(default_factory=list)
    # (status, body[, extra headers]) consumed in order; then 200
    responses: list[tuple[Any, ...]] = field(default_factory=list)

    def opener(self) -> Any:
        return notify_http.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture
def http_server() -> Iterator[HttpRecorder]:
    rec = HttpRecorder()

    class Handler(http.server.BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            rec.requests.append(Recorded(self.command, self.path, dict(self.headers.items()), body))
            status, payload, *extra = rec.responses.pop(0) if rec.responses else (200, b'{"ok":true}')
            self.send_response(status)
            for key, value in (extra[0] if extra else {}).items():
                self.send_header(key, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = _handle

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    rec.url = f"http://127.0.0.1:{server.server_address[1]}"
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    try:
        yield rec
    finally:
        server.shutdown()
        server.server_close()


# ── loopback SMTP sink ────────────────────────────────────────────────────────


@dataclass
class SmtpSink:
    port: int = 0
    messages: list[tuple[str, list[str], bytes]] = field(default_factory=list)


@pytest.fixture
def smtp_sink() -> Iterator[SmtpSink]:
    """A minimal plain SMTP server (EHLO/MAIL/RCPT/DATA/QUIT) on 127.0.0.1."""
    sink = SmtpSink()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            def say(line: str) -> None:
                self.wfile.write(line.encode() + b"\r\n")

            say("220 sink ESMTP")
            sender, rcpts = "", []
            while line := self.rfile.readline():
                cmd = line.decode().strip()
                upper = cmd.upper()
                if upper.startswith(("EHLO", "HELO")):
                    say("250 sink")
                elif upper.startswith("MAIL FROM:"):
                    sender = cmd[10:].strip("<> ")
                    say("250 ok")
                elif upper.startswith("RCPT TO:"):
                    rcpts.append(cmd[8:].strip("<> "))
                    say("250 ok")
                elif upper == "DATA":
                    say("354 go")
                    data = b""
                    while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                        data += chunk
                    sink.messages.append((sender, rcpts, data))
                    say("250 queued")
                elif upper == "QUIT":
                    say("221 bye")
                    return
                else:
                    say("250 ok")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    sink.port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    try:
        yield sink
    finally:
        server.shutdown()
        server.server_close()
