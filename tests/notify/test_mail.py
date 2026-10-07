"""A15: email notifier — STARTTLS/SSL/none, login, attachments, errors."""

from __future__ import annotations

import email
import email.policy
import smtplib
import ssl
from pathlib import Path
from typing import Any, ClassVar

import pytest

from pbv.config import EmailConfig
from pbv.core import NotifyWhen, PbvError, Status
from pbv.notify import EmailNotifier

from .conftest import PNG, SECRET, SmtpSink, make_report, make_vm


class FakeSMTP:
    """Records the SMTP conversation; optionally raises at one step."""

    instances: ClassVar[list[FakeSMTP]] = []

    def __init__(self, host: str, port: int, timeout: float, *, fail_at: str = "", exc: Exception | None = None):
        self.args = (host, port, timeout)
        self.calls: list[str] = []
        self.messages: list[Any] = []
        self.login_args: tuple[str, str] | None = None
        self.context: Any = None
        self.fail_at = fail_at
        self.exc = exc
        FakeSMTP.instances.append(self)

    def _maybe_fail(self, step: str) -> None:
        self.calls.append(step)
        if step == self.fail_at and self.exc is not None:
            raise self.exc

    def ehlo(self) -> None:
        self._maybe_fail("ehlo")

    def starttls(self, context: Any = None) -> None:
        self.context = context
        self._maybe_fail("starttls")

    def login(self, user: str, password: str) -> None:
        self.login_args = (user, password)
        self._maybe_fail("login")

    def send_message(self, msg: Any) -> None:
        self.messages.append(msg)
        self._maybe_fail("send_message")

    def quit(self) -> None:
        self._maybe_fail("quit")


@pytest.fixture(autouse=True)
def _reset() -> None:
    FakeSMTP.instances.clear()


def cfg(**kw: Any) -> EmailConfig:
    base: dict[str, Any] = {
        "enabled": True,
        "when": NotifyWhen.ALWAYS,
        "smtp_host": "mail.example.org",
        "smtp_port": 587,
        "sender": "pbv@example.org",
        "to": ("ops@example.org", "oncall@example.org"),
    }
    base.update(kw)
    return EmailConfig(**base)


def factory(**kw: Any):
    return lambda host, port, timeout: FakeSMTP(host, port, timeout, **kw)


def test_starttls_login_and_headers() -> None:
    n = EmailNotifier(cfg(username="pbv", password=SECRET, timeout_s=7), smtp_factory=factory())
    report = make_report([make_vm(101), make_vm(105, Status.FAIL)])
    n.run_finished(report)
    (smtp,) = FakeSMTP.instances
    assert smtp.args == ("mail.example.org", 587, 7)
    assert smtp.calls == ["ehlo", "starttls", "ehlo", "login", "send_message", "quit"]
    assert isinstance(smtp.context, ssl.SSLContext)
    assert smtp.context.verify_mode == ssl.CERT_REQUIRED
    assert smtp.login_args == ("pbv", SECRET)
    msg = smtp.messages[0]
    assert msg["Subject"] == "[pbv] FAIL 1/2 VMs on restore01 (1 pass, 1 fail)"
    assert msg["From"] == "pbv@example.org"
    assert msg["To"] == "ops@example.org, oncall@example.org"
    assert msg["Date"] and msg["Message-ID"].endswith("@example.org>")
    assert msg.get_content_type() == "text/plain"
    assert msg.get_content_charset() == "utf-8"
    assert "[FAIL] vm105" in msg.get_content()


def test_ssl_mode_has_no_starttls_and_no_login_without_username() -> None:
    EmailNotifier(cfg(security="ssl", smtp_port=465), smtp_factory=factory()).run_finished(make_report([make_vm(1)]))
    assert FakeSMTP.instances[0].calls == ["send_message", "quit"]


def test_none_mode() -> None:
    EmailNotifier(cfg(security="none", username="u", password="p"), smtp_factory=factory()).run_finished(
        make_report([make_vm(1)])
    )
    assert FakeSMTP.instances[0].calls == ["login", "send_message", "quit"]


def test_default_factory_selects_ssl_class(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, dict[str, Any]]] = []

    def fake(kind: str):
        def ctor(host: str, port: int, **kw: Any) -> FakeSMTP:
            seen.append((kind, kw))
            return FakeSMTP(host, port, kw["timeout"])

        return ctor

    monkeypatch.setattr(smtplib, "SMTP_SSL", fake("ssl"))
    monkeypatch.setattr(smtplib, "SMTP", fake("plain"))
    EmailNotifier(cfg(security="ssl")).run_finished(make_report([make_vm(1)]))
    EmailNotifier(cfg(security="starttls")).run_finished(make_report([make_vm(1)]))
    assert [k for k, _ in seen] == ["ssl", "plain"]
    assert isinstance(seen[0][1]["context"], ssl.SSLContext)


def test_attachment_limits(tmp_path: Path) -> None:
    shots = []
    for i in range(7):
        p = tmp_path / f"shot{i}.png"
        p.write_bytes(PNG)
        shots.append(str(p))
    shots.append(str(tmp_path / "missing.png"))
    (tmp_path / "x.ppm").write_bytes(b"P6")
    report = make_report([make_vm(101, Status.FAIL, screenshots=[*shots, str(tmp_path / "x.ppm")])])
    EmailNotifier(cfg(), smtp_factory=factory()).run_finished(report)
    msg = FakeSMTP.instances[0].messages[0]
    atts = list(msg.iter_attachments())
    assert [a.get_filename() for a in atts] == [f"shot{i}.png" for i in range(5)]
    assert atts[0].get_content_type() == "image/png"
    assert atts[0].get_content() == PNG
    assert "4 screenshot(s) not attached (limit 5 files / 10 MiB" in msg.get_body(("plain",)).get_content()


def test_attachment_size_limit(tmp_path: Path) -> None:
    big = tmp_path / "big.png"
    big.write_bytes(PNG + b"\x00" * (6 * 1024 * 1024))
    big2 = tmp_path / "big2.png"
    big2.write_bytes(big.read_bytes())
    small = tmp_path / "small.png"
    small.write_bytes(PNG)
    report = make_report([make_vm(101, Status.FAIL, screenshots=[str(big), str(big2), str(small)])])
    EmailNotifier(cfg(), smtp_factory=factory()).run_finished(report)
    msg = FakeSMTP.instances[0].messages[0]
    assert [a.get_filename() for a in msg.iter_attachments()] == ["big.png", "small.png"]


def test_attach_disabled(tmp_path: Path) -> None:
    p = tmp_path / "s.png"
    p.write_bytes(PNG)
    report = make_report([make_vm(101, Status.FAIL, screenshots=[str(p)])])
    EmailNotifier(cfg(attach_screenshots=False), smtp_factory=factory()).run_finished(report)
    assert list(FakeSMTP.instances[0].messages[0].iter_attachments()) == []


def test_gating_when_and_per_vm() -> None:
    n = EmailNotifier(cfg(when=NotifyWhen.FAILURE), smtp_factory=factory())
    ok = make_report([make_vm(1)])
    n.run_finished(ok)
    n.vm_finished(ok.vms[0], ok)
    assert FakeSMTP.instances == []
    bad_vm = make_vm(2, Status.FAIL)
    n.vm_finished(bad_vm, ok)  # per_vm off
    assert FakeSMTP.instances == []
    n = EmailNotifier(cfg(when=NotifyWhen.FAILURE, per_vm=True), smtp_factory=factory())
    n.vm_finished(ok.vms[0], ok)
    assert FakeSMTP.instances == []
    n.vm_finished(bad_vm, ok)
    assert FakeSMTP.instances[0].messages[0]["Subject"] == "[pbv] FAIL vm2 (2) on restore01"
    EmailNotifier(cfg(when=NotifyWhen.NEVER), smtp_factory=factory()).run_finished(make_report([bad_vm]))
    assert len(FakeSMTP.instances) == 1


@pytest.mark.parametrize(
    ("fail_at", "exc", "expected"),
    [
        (
            "login",
            smtplib.SMTPAuthenticationError(535, f"bad creds {SECRET}".encode()),
            "SMTPAuthenticationError (535)",
        ),
        ("starttls", smtplib.SMTPNotSupportedError("STARTTLS not supported"), "SMTPNotSupportedError"),
        (
            "send_message",
            smtplib.SMTPRecipientsRefused({"a@b": (550, b"no such user")}),
            "SMTPRecipientsRefused (550)",
        ),
        ("send_message", ConnectionResetError(104, "Connection reset by peer"), "ConnectionResetError: Connection"),
        ("ehlo", ssl.SSLError(1, "[SSL: CERTIFICATE_VERIFY_FAILED]"), "SSLError"),
    ],
)
def test_smtp_errors_are_notify_fail_and_secret_free(fail_at: str, exc: Exception, expected: str) -> None:
    n = EmailNotifier(cfg(username="pbv", password=SECRET), smtp_factory=factory(fail_at=fail_at, exc=exc))
    with pytest.raises(PbvError) as ei:
        n.run_finished(make_report([make_vm(1)]))
    assert ei.value.code == "NOTIFY_FAIL"
    assert str(ei.value).startswith("email: ")
    assert expected in str(ei.value)
    assert SECRET not in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__
    assert FakeSMTP.instances[0].calls[-1] == "quit"  # connection closed even on failure


def test_connect_failure() -> None:
    def refuse(host: str, port: int, timeout: float) -> None:
        raise ConnectionRefusedError(111, "Connection refused")

    with pytest.raises(PbvError, match=r"^email: cannot connect to mail.example.org:587 \(ConnectionRefusedError"):
        EmailNotifier(cfg(), smtp_factory=refuse).run_finished(make_report([make_vm(1)]))


def test_quit_failure_is_ignored() -> None:
    n = EmailNotifier(cfg(), smtp_factory=factory(fail_at="quit", exc=smtplib.SMTPServerDisconnected("gone")))
    n.run_finished(make_report([make_vm(1)]))
    assert len(FakeSMTP.instances[0].messages) == 1


def test_unexpected_exception_is_wrapped(caplog: pytest.LogCaptureFixture) -> None:
    n = EmailNotifier(
        cfg(username="u", password=SECRET), smtp_factory=factory(fail_at="login", exc=ValueError(f"oops {SECRET}"))
    )
    caplog.set_level("DEBUG", logger="pbv.notify")
    with pytest.raises(PbvError, match=r"^email: unexpected ValueError$"):
        n.run_finished(make_report([make_vm(1)]))
    assert SECRET not in caplog.text
    assert "oops ***" in caplog.text


def test_repr_has_no_password() -> None:
    assert SECRET not in repr(EmailNotifier(cfg(username="u", password=SECRET)))


def test_real_smtp_loopback(smtp_sink: SmtpSink) -> None:
    n = EmailNotifier(cfg(smtp_host="127.0.0.1", smtp_port=smtp_sink.port, security="none", timeout_s=5))
    n.run_finished(make_report([make_vm(101, Status.FAIL, name="wëb")]))
    (sender, rcpts, data) = smtp_sink.messages[0]
    assert sender == "pbv@example.org"
    assert rcpts == ["ops@example.org", "oncall@example.org"]
    msg = email.message_from_bytes(data, policy=email.policy.default)
    assert msg["Subject"] == "[pbv] FAIL 1/1 VMs on restore01 (1 fail)"
    assert "[FAIL] wëb — vmid 101" in msg.get_content()
