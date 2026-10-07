"""A15: ntfy notifier against a loopback HTTP server."""

from __future__ import annotations

import base64
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from pbv.config import NtfyConfig
from pbv.core import NotifyWhen, PbvError, Status
from pbv.notify import NtfyNotifier
from pbv.notify.ntfy import encode_header, truncate_bytes
from pbv.notify.render import TRUNCATION_NOTE

from .conftest import PNG, SECRET, HttpRecorder, check, make_report, make_vm


def cfg(server: str, **kw: Any) -> NtfyConfig:
    base: dict[str, Any] = {"enabled": True, "when": NotifyWhen.ALWAYS, "server": server, "topic": "pbv-alerts"}
    base.update(kw)
    return NtfyConfig(**base)


def notifier(srv: HttpRecorder, sleeps: list[float] | None = None, **kw: Any) -> NtfyNotifier:
    sink = sleeps if sleeps is not None else []
    return NtfyNotifier(cfg(srv.url, **kw), opener=srv.opener(), sleep=sink.append)


def test_post_headers_and_body(http_server: HttpRecorder) -> None:
    n = notifier(http_server, token=SECRET, click_url="https://pbv.example/latest")
    report = make_report([make_vm(101), make_vm(105, Status.FAIL)])
    n.run_finished(report)
    (req,) = http_server.requests
    assert req.method == "POST"
    assert req.path == "/pbv-alerts"
    h = req.headers
    assert h["Title"] == "[pbv] FAIL 1/2 VMs on restore01 (1 pass, 1 fail)"
    assert h["Priority"] == "high"
    assert h["Tags"] == "rotating_light"
    assert h["Click"] == "https://pbv.example/latest"
    assert h["Authorization"] == f"Bearer {SECRET}"
    assert "Markdown" not in h  # plain-text body
    assert h["Content-Type"] == "text/plain; charset=utf-8"
    assert req.body.decode().startswith("pbv run 20261007T020000Z-ab12 on restore01: FAIL")


def test_ok_priority_tags_and_no_auth(http_server: HttpRecorder) -> None:
    notifier(http_server, tags_ok=("a", "b"), priority_ok="low").run_finished(make_report([make_vm(1)]))
    h = http_server.requests[0].headers
    assert h["Priority"] == "low"
    assert h["Tags"] == "a,b"
    assert "Authorization" not in h and "Click" not in h


def test_non_ascii_title_is_rfc2047(http_server: HttpRecorder) -> None:
    report = make_report([make_vm(1, Status.FAIL, name="wëb")])
    notifier(http_server, per_vm=True).vm_finished(report.vms[0], report)
    title = http_server.requests[0].headers["Title"]
    assert title.startswith("=?UTF-8?B?") and title.endswith("?=")
    assert base64.b64decode(title[10:-2]).decode() == "[pbv] FAIL wëb (1) on restore01"
    assert encode_header("plain") == "plain"


def test_body_truncated_to_4096_bytes(http_server: HttpRecorder) -> None:
    checks = [check(f"command:c{i}", Status.FAIL, "é" * 150) for i in range(60)]
    report = make_report([make_vm(1, Status.FAIL, checks=checks)])
    notifier(http_server).run_finished(report)
    body = http_server.requests[0].body
    assert len(body) <= 4096
    assert body.decode("utf-8").endswith(TRUNCATION_NOTE)
    assert truncate_bytes("short") == b"short"


def test_retry_429_and_5xx_with_backoff(http_server: HttpRecorder) -> None:
    http_server.responses = [(429, b'{"error":"limit"}'), (503, b"busy")]
    sleeps: list[float] = []
    notifier(http_server, sleeps).run_finished(make_report([make_vm(1)]))
    assert len(http_server.requests) == 3
    assert sleeps == [1.0, 3.0]


def test_retries_exhausted(http_server: HttpRecorder) -> None:
    http_server.responses = [(500, b"x"), (502, b"x"), (500, b'{"code":50001,"error":"internal"}')]
    sleeps: list[float] = []
    with pytest.raises(PbvError, match=r"^ntfy: HTTP 500 Internal Server Error: internal$") as ei:
        notifier(http_server, sleeps).run_finished(make_report([make_vm(1)]))
    assert ei.value.code == "NOTIFY_FAIL"
    assert len(http_server.requests) == 3 and sleeps == [1.0, 3.0]


def test_403_not_retried_and_secret_free(http_server: HttpRecorder) -> None:
    http_server.responses = [(403, f'{{"error":"forbidden {SECRET}"}}'.encode())]
    sleeps: list[float] = []
    with pytest.raises(PbvError) as ei:
        notifier(http_server, sleeps, token=SECRET).run_finished(make_report([make_vm(1)]))
    assert str(ei.value) == "ntfy: HTTP 403 Forbidden: forbidden ***"
    assert len(http_server.requests) == 1 and sleeps == []
    assert http_server.url not in str(ei.value)


def test_error_body_snippet_capped(http_server: HttpRecorder) -> None:
    http_server.responses = [(400, b"x" * 5000)]
    with pytest.raises(PbvError) as ei:
        notifier(http_server).run_finished(make_report([make_vm(1)]))
    assert str(ei.value) == "ntfy: HTTP 400 Bad Request: " + "x" * 200


def test_connection_failure_retried_then_fails() -> None:
    calls: list[Any] = []

    def opener(req: Any, timeout: float) -> Any:
        calls.append((req.full_url, timeout))
        raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))

    sleeps: list[float] = []
    n = NtfyNotifier(cfg("http://127.0.0.1:9", token=SECRET, timeout_s=4), opener=opener, sleep=sleeps.append)
    with pytest.raises(PbvError, match=r"^ntfy: connection failed \(ConnectionRefusedError: Connection refused\)$"):
        n.run_finished(make_report([make_vm(1)]))
    assert len(calls) == 3 and calls[0] == ("http://127.0.0.1:9/pbv-alerts", 4)
    assert sleeps == [1.0, 3.0]


def test_attachments_put_at_most_three(http_server: HttpRecorder, tmp_path: Path) -> None:
    shots = []
    for i in range(4):
        p = tmp_path / f"s{i}.png"
        p.write_bytes(PNG)
        shots.append(str(p))
    report = make_report([make_vm(1, Status.FAIL, screenshots=shots)])
    notifier(http_server, attach_screenshots=True, token=SECRET).run_finished(report)
    puts = [r for r in http_server.requests if r.method == "PUT"]
    assert [r.headers["Filename"] for r in puts] == ["s0.png", "s1.png", "s2.png"]
    assert all(r.body == PNG and r.path == "/pbv-alerts" for r in puts)
    assert puts[0].headers["Title"].startswith("[pbv] FAIL")
    assert puts[0].headers["Authorization"] == f"Bearer {SECRET}"


def test_no_attachments_by_default(http_server: HttpRecorder, tmp_path: Path) -> None:
    p = tmp_path / "s.png"
    p.write_bytes(PNG)
    notifier(http_server).run_finished(make_report([make_vm(1, Status.FAIL, screenshots=[str(p)])]))
    assert [r.method for r in http_server.requests] == ["POST"]


def test_gating(http_server: HttpRecorder) -> None:
    n = notifier(http_server, when=NotifyWhen.FAILURE)
    ok = make_report([make_vm(1)])
    n.run_finished(ok)
    n.vm_finished(make_vm(2, Status.FAIL), ok)  # per_vm off
    assert http_server.requests == []
    n.run_finished(make_report([make_vm(1)], status=Status.ERROR, interrupted=True))
    assert len(http_server.requests) == 1


def test_repr_has_no_token(http_server: HttpRecorder) -> None:
    assert SECRET not in repr(notifier(http_server, token=SECRET))
