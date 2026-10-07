"""Adversarial review tests for pbv.notify (skipped unless PBV_REVIEW=1)."""

from __future__ import annotations

import http.server
import os
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from pbv.config import NtfyConfig
from pbv.core import BackupRef, NotifyWhen, PbvError, RunReport, Status, VmResult
from pbv.notify import NtfyNotifier, render_text

REVIEW = os.environ.get("PBV_REVIEW") == "1"


def review_bug(reason: str) -> None:
    if not REVIEW:
        pytest.skip("BUG: " + reason)


T0 = "2026-10-07T02:00:00Z"


def make_vm(vmid: int, status: Status = Status.PASS, **kw: Any) -> VmResult:
    defaults: dict[str, Any] = {
        "temp_vmid": 900000 + vmid,
        "name": f"vm{vmid}",
        "started_at": T0,
        "duration_s": 81.0,
        "backup": BackupRef(volid=f"pbs:backup/vm/{vmid}/2026-10-06T02:00:00Z", vmid=vmid, ctime=0, size=0),
    }
    defaults.update(kw)
    return VmResult(vmid=vmid, status=status, **defaults)


def make_report(vms: list[VmResult], status: Status, **kw: Any) -> RunReport:
    defaults: dict[str, Any] = {
        "run_id": "20261007T020000Z-ab12",
        "target_node": "restore01",
        "started_at": T0,
        "finished_at": "2026-10-07T02:10:00Z",
        "duration_s": 600.0,
    }
    defaults.update(kw)
    return RunReport(vms=vms, status=status, **defaults)


# ── rendering ─────────────────────────────────────────────────────────────────


def test_render_text_reports_sweep_failures() -> None:
    review_bug("render_text ignores RunReport.sweep_failures (leftover temp VMs still present)")
    report = make_report(
        [make_vm(105)],
        Status.ERROR,
        sweep_failures=["900777: CLEANUP_FAIL destroy task failed"],
    )
    text = render_text(report)
    # The run is ERROR solely because temp VM 900777 survived the startup sweep;
    # the notification must say so (it is a manual-cleanup situation).
    assert "900777" in text, text


# ── ntfy: POST silently downgraded to GET on 301/302/303 ─────────────────────


@pytest.fixture
def redirect_server() -> Iterator[tuple[str, list[tuple[str, str, bytes]]]]:
    seen: list[tuple[str, str, bytes]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            seen.append((self.command, self.path, body))
            if self.path.startswith("/topic"):
                # e.g. a reverse proxy redirecting http -> https / to a canonical host
                self.send_response(301)
                self.send_header("Location", "/moved/topic")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = b"<html>ntfy web app</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = _handle

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def test_ntfy_redirect_does_not_silently_drop_message(
    redirect_server: tuple[str, list[tuple[str, str, bytes]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    review_bug("default urllib opener turns a 301'd POST into a body-less GET; ntfy reports success")
    for var in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    url, seen = redirect_server
    cfg = NtfyConfig(enabled=True, when=NotifyWhen.ALWAYS, server=url, topic="topic", timeout_s=2)
    notifier = NtfyNotifier(cfg, sleep=lambda _s: None)  # default opener, as in production
    report = make_report([make_vm(105, Status.FAIL)], Status.FAIL)
    try:
        notifier.run_finished(report)
    except PbvError as exc:
        assert exc.code == "NOTIFY_FAIL"
        return
    # No error raised: then the message must actually have been published somewhere.
    published = [(m, p) for m, p, body in seen if m in ("POST", "PUT") and body and not p.startswith("/topic")]
    assert published, f"notifier reported success but the server only saw: {[(m, p) for m, p, _ in seen]}"
