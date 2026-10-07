"""build_notifiers, send_test and the notifier error boundary."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from pbv.config import EmailConfig, JsonConfig, NotifyConfig, NtfyConfig, TelegramConfig
from pbv.core import Notifier, NotifyWhen, PbvError, RunReport, Status
from pbv.notify import (
    EmailNotifier,
    JsonNotifier,
    NtfyNotifier,
    TelegramNotifier,
    build_notifiers,
    send_test,
)
from pbv.notify.base import BaseNotifier
from pbv.testing.fakes import RecordingNotifier

from .conftest import SECRET, HttpRecorder, make_report, make_vm


def full_cfg(tmp_path: Path, server: str = "http://127.0.0.1:9") -> NotifyConfig:
    return NotifyConfig(
        email=EmailConfig(enabled=True, smtp_host="mail", sender="a@b", to=("c@d",), password=SECRET, username="u"),
        ntfy=NtfyConfig(enabled=True, server=server, topic="t", token=SECRET),
        json=JsonConfig(dir=tmp_path / "reports"),
        telegram=TelegramConfig(enabled=True, token=SECRET, chat_id="1"),
    )


def test_build_order_and_protocol(tmp_path: Path) -> None:
    ns = build_notifiers(full_cfg(tmp_path), run_dir=tmp_path)
    assert [type(n) for n in ns] == [EmailNotifier, NtfyNotifier, TelegramNotifier, JsonNotifier]
    assert [n.name for n in ns] == ["email", "ntfy", "telegram", "json"]
    assert all(isinstance(n, Notifier) for n in ns)
    assert all(SECRET not in repr(n) for n in ns)


def test_build_defaults_only_json(tmp_path: Path) -> None:
    ns = build_notifiers(NotifyConfig(json=JsonConfig(dir=tmp_path)))
    assert [n.name for n in ns] == ["json"]
    assert build_notifiers(NotifyConfig(json=JsonConfig(enabled=False))) == []


def test_send_test_bypasses_when_and_reports_errors(tmp_path: Path, http_server: HttpRecorder) -> None:
    sent: list[Any] = []

    class Smtp:
        def __init__(self, *a: Any) -> None:
            pass

        def ehlo(self) -> None: ...
        def starttls(self, context: Any = None) -> None: ...
        def quit(self) -> None: ...

        def login(self, u: str, p: str) -> None:
            import smtplib

            raise smtplib.SMTPAuthenticationError(535, b"nope")

        def send_message(self, m: Any) -> None:
            sent.append(m)

    cfg = NotifyConfig(
        email=EmailConfig(
            enabled=True, when=NotifyWhen.NEVER, smtp_host="m", sender="a@b", to=("c@d",), username="u", password=SECRET
        ),
        ntfy=NtfyConfig(enabled=True, when=NotifyWhen.FAILURE, server=http_server.url, topic="t", token=SECRET),
        json=JsonConfig(dir=tmp_path, when=NotifyWhen.FAILURE),
    )
    out = io.StringIO()
    ns = build_notifiers(cfg, smtp_factory=Smtp, opener=http_server.opener(), stdout=out)
    ns.append(RecordingNotifier())
    result = send_test(ns, node="restore01")
    assert result["email"] == "email: SMTPAuthenticationError (535)"
    assert result["ntfy"] == "ok"
    assert result["json"] == "ok"
    assert list(result.values()).count("ok") == 3
    assert http_server.requests[0].headers["Title"] == "[pbv] PASS 1/1 VMs on restore01"
    files = sorted(p.name for p in tmp_path.iterdir())
    assert len(files) == 1 and files[0].endswith("-test.json")  # no latest.json for a test
    assert json.loads((tmp_path / files[0]).read_text())["status"] == "pass"
    assert SECRET not in json.dumps(result)


def test_send_test_foreign_notifier_errors() -> None:
    class Boom:
        name = "boom"

        def vm_finished(self, result: Any, report: Any) -> None: ...

        def run_finished(self, report: RunReport) -> None:
            raise RuntimeError("kaput")

    class Fails:
        name = "fails"

        def vm_finished(self, result: Any, report: Any) -> None: ...

        def run_finished(self, report: RunReport) -> None:
            raise PbvError("fails: nope", code="NOTIFY_FAIL")

    assert send_test([Boom(), Fails()]) == {"boom": "boom: unexpected RuntimeError", "fails": "fails: nope"}


def test_guard_converts_foreign_pbv_error_codes() -> None:
    class N(BaseNotifier):
        name = "x"
        when = NotifyWhen.ALWAYS

        def _send_run(self, report: RunReport) -> None:
            raise PbvError(f"timeout talking {SECRET}", code="TIMEOUT")

    n = N()
    n._secrets = (SECRET,)
    with pytest.raises(PbvError) as ei:
        n.run_finished(make_report([make_vm(1)]))
    assert ei.value.code == "NOTIFY_FAIL"
    assert str(ei.value) == "x: TIMEOUT timeout talking ***"


def test_notifier_failure_does_not_touch_report(tmp_path: Path) -> None:
    """A failing notifier raises NOTIFY_FAIL but never mutates the run's statuses."""
    n = NtfyNotifier(
        NtfyConfig(enabled=True, when=NotifyWhen.ALWAYS, server="http://x", topic="t"),
        opener=lambda req, timeout: (_ for _ in ()).throw(OSError(113, "No route to host")),
        sleep=lambda s: None,
    )
    report = make_report([make_vm(1, Status.FAIL)])
    before = json.dumps(report.__dict__, default=str)
    with pytest.raises(PbvError, match=r"^ntfy: connection failed \(OSError: No route to host\)$") as ei:
        n.run_finished(report)
    assert ei.value.code == "NOTIFY_FAIL"
    assert json.dumps(report.__dict__, default=str) == before
