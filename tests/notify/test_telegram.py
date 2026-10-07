"""Telegram notifier against a loopback HTTP server; the token never leaks."""

from __future__ import annotations

import urllib.parse
from typing import Any

import pytest

from pbv.config import TelegramConfig
from pbv.core import NotifyWhen, PbvError, Status
from pbv.notify import TelegramNotifier
from pbv.notify.render import TRUNCATION_NOTE

from .conftest import SECRET, HttpRecorder, check, make_report, make_vm


def notifier(srv: HttpRecorder, sleeps: list[float] | None = None, **kw: Any) -> TelegramNotifier:
    base: dict[str, Any] = {"enabled": True, "when": NotifyWhen.ALWAYS, "token": SECRET, "chat_id": "-100123"}
    base.update(kw)
    sink = sleeps if sleeps is not None else []
    return TelegramNotifier(TelegramConfig(**base), opener=srv.opener(), sleep=sink.append, api_base=srv.url)


def form(body: bytes) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(body.decode()))


def test_send_message_fail(http_server: HttpRecorder) -> None:
    notifier(http_server, thread_id="42").run_finished(make_report([make_vm(1, Status.FAIL)]))
    (req,) = http_server.requests
    assert req.method == "POST"
    assert req.path == f"/bot{SECRET}/sendMessage"
    f = form(req.body)
    assert f["chat_id"] == "-100123"
    assert f["message_thread_id"] == "42"
    assert "disable_notification" not in f and "parse_mode" not in f
    assert f["text"].startswith("pbv run 20261007T020000Z-ab12 on restore01: FAIL")


def test_pass_is_silent_and_no_thread(http_server: HttpRecorder) -> None:
    notifier(http_server).run_finished(make_report([make_vm(1)]))
    f = form(http_server.requests[0].body)
    assert f["disable_notification"] == "true"
    assert "message_thread_id" not in f


def test_text_truncated_to_4096_chars(http_server: HttpRecorder) -> None:
    checks = [check(f"command:c{i}", Status.FAIL, "x" * 150) for i in range(60)]
    notifier(http_server).run_finished(make_report([make_vm(1, Status.FAIL, checks=checks)]))
    text = form(http_server.requests[0].body)["text"]
    assert len(text) == 4096 and text.endswith(TRUNCATION_NOTE)


def test_per_vm(http_server: HttpRecorder) -> None:
    report = make_report([make_vm(1, Status.FAIL, name="db")])
    notifier(http_server, per_vm=True, when=NotifyWhen.FAILURE).vm_finished(report.vms[0], report)
    assert form(http_server.requests[0].body)["text"].startswith("pbv run 20261007T020000Z-ab12 on restore01: VM db")


def test_http_error_never_contains_token_or_url(http_server: HttpRecorder) -> None:
    http_server.responses = [(400, f'{{"ok":false,"description":"Bad Request: bot{SECRET} chat not found"}}'.encode())]
    with pytest.raises(PbvError) as ei:
        notifier(http_server).run_finished(make_report([make_vm(1)]))
    msg = str(ei.value)
    assert ei.value.code == "NOTIFY_FAIL"
    assert msg == "telegram: HTTP 400 Bad Request: Bad Request: bot*** chat not found"
    assert SECRET not in msg and http_server.url not in msg
    assert ei.value.__cause__ is None


def test_429_retried(http_server: HttpRecorder) -> None:
    http_server.responses = [(429, b'{"ok":false,"description":"Too Many Requests"}')]
    sleeps: list[float] = []
    notifier(http_server, sleeps).run_finished(make_report([make_vm(1)]))
    assert len(http_server.requests) == 2 and sleeps == [1.0]


def test_unexpected_opener_error_is_secret_free(caplog: pytest.LogCaptureFixture) -> None:
    def opener(req: Any, timeout: float) -> Any:
        raise ValueError(f"bad url {req.full_url}")

    caplog.set_level("DEBUG", logger="pbv.notify")
    n = TelegramNotifier(TelegramConfig(enabled=True, when=NotifyWhen.ALWAYS, token=SECRET, chat_id="1"), opener=opener)
    with pytest.raises(PbvError, match=r"^telegram: unexpected ValueError$"):
        n.run_finished(make_report([make_vm(1)]))
    assert SECRET not in caplog.text
    assert SECRET not in repr(n)


def test_text_truncated_to_4096_utf16_units_with_emoji(http_server: HttpRecorder) -> None:
    checks = [check(f"command:c{i}", Status.FAIL, "🔥" * 75) for i in range(60)]
    notifier(http_server).run_finished(make_report([make_vm(1, Status.FAIL, checks=checks)]))
    text = form(http_server.requests[0].body)["text"]
    text.encode("utf-8")  # strict: raises on a lone surrogate
    units = len(text.encode("utf-16-le")) // 2
    assert 4095 <= units <= 4096 and text.endswith(TRUNCATION_NOTE)
    assert len(text) < 4096  # code points undercount what Telegram measures


def test_per_vm_text_truncated_by_utf16(http_server: HttpRecorder) -> None:
    checks = [check(f"command:c{i}", Status.FAIL, "😀" * 75) for i in range(60)]
    report = make_report([make_vm(1, Status.FAIL, checks=checks)])
    notifier(http_server, per_vm=True).vm_finished(report.vms[0], report)
    text = form(http_server.requests[0].body)["text"]
    assert len(text.encode("utf-16-le")) // 2 <= 4096 and text.endswith(TRUNCATION_NOTE)


def test_sweep_failure_alerts_loudly(http_server: HttpRecorder) -> None:
    report = make_report([make_vm(1)], status=Status.PASS, sweep_failures=["900777: CLEANUP_FAIL boom"])
    notifier(http_server, when=NotifyWhen.FAILURE).run_finished(report)
    f = form(http_server.requests[0].body)
    assert "disable_notification" not in f
    assert "MANUAL CLEANUP REQUIRED: VM 900777 on restore01 (startup sweep: CLEANUP_FAIL boom)" in f["text"]


def test_redirect_refused(http_server: HttpRecorder) -> None:
    http_server.responses = [(302, b"", {"Location": "/elsewhere"})]
    with pytest.raises(PbvError, match=r"^telegram: HTTP 302 redirect refused; check server URL$"):
        notifier(http_server).run_finished(make_report([make_vm(1)]))
    assert [r.method for r in http_server.requests] == ["POST"]
