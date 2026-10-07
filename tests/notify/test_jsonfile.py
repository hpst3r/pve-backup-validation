"""A15: JSON report — atomic write, perms, latest, partial lifecycle, retention, stdout."""

from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from pbv.config import JsonConfig
from pbv.core import NotifyWhen, PbvError, Status, report_to_dict
from pbv.notify import JsonNotifier
from pbv.notify import jsonfile

from .conftest import make_report, make_vm

RUN = "20261007T020000Z-ab12"
NOW = 2_000_000_000.0


def notifier(d: Path, *, out: io.StringIO | None = None, **kw: Any) -> JsonNotifier:
    return JsonNotifier(JsonConfig(dir=d, **kw), stdout=out, clock=lambda: NOW)


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_final_report_latest_and_perms(tmp_path: Path) -> None:
    d = tmp_path / "reports" / "nested"
    report = make_report([make_vm(101), make_vm(105, Status.FAIL, name="wëb")])
    notifier(d).run_finished(report)
    final = d / f"{RUN}.json"
    latest = d / "latest.json"
    assert mode(d) == 0o750
    assert mode(final) == 0o640 and mode(latest) == 0o640
    assert not latest.is_symlink()
    assert final.read_text(encoding="utf-8") == latest.read_text(encoding="utf-8")
    doc = json.loads(final.read_text(encoding="utf-8"))
    assert doc == json.loads(json.dumps(report_to_dict(report)))
    assert doc["counts"]["fail"] == 1 and doc["status"] == "fail"
    assert "wëb" in final.read_text(encoding="utf-8")  # ensure_ascii=False
    assert final.read_text(encoding="utf-8") == jsonfile.dump_report(report)
    assert sorted(p.name for p in d.iterdir()) == [f"{RUN}.json", "latest.json"]  # no temp files left


def test_write_latest_disabled(tmp_path: Path) -> None:
    notifier(tmp_path, write_latest=False).run_finished(make_report([make_vm(1)]))
    assert not (tmp_path / "latest.json").exists()


def test_partial_lifecycle(tmp_path: Path) -> None:
    n = notifier(tmp_path)
    vm1 = make_vm(101)
    report = make_report([vm1])
    n.vm_finished(vm1, report)
    partial = tmp_path / f"{RUN}.partial.json"
    assert json.loads(partial.read_text())["vms"][0]["vmid"] == 101
    assert mode(partial) == 0o640
    vm2 = make_vm(102, Status.FAIL)
    report.vms.append(vm2)
    n.vm_finished(vm2, report)
    assert [v["vmid"] for v in json.loads(partial.read_text())["vms"]] == [101, 102]
    n.run_finished(report)
    assert not partial.exists()
    assert (tmp_path / f"{RUN}.json").exists()


def test_when_failure_skips_pass_but_still_removes_partial(tmp_path: Path) -> None:
    n = notifier(tmp_path, when=NotifyWhen.FAILURE)
    report = make_report([make_vm(1)])
    n.vm_finished(report.vms[0], report)
    n.run_finished(report)
    assert list(tmp_path.iterdir()) == []
    bad = make_report([make_vm(1)], status=Status.ERROR, interrupted=True)
    n.run_finished(bad)
    assert (tmp_path / f"{RUN}.json").exists()


def test_when_never_writes_nothing(tmp_path: Path) -> None:
    n = notifier(tmp_path / "r", when=NotifyWhen.NEVER)
    report = make_report([make_vm(1, Status.FAIL)])
    n.vm_finished(report.vms[0], report)
    n.run_finished(report)
    assert not (tmp_path / "r").exists()


def _touch(p: Path, mtime: float) -> None:
    p.write_text("{}")
    os.utime(p, (mtime, mtime))


def test_retention(tmp_path: Path) -> None:
    old = [f"2026100{i}T020000Z-00{i}a.json" for i in range(1, 6)]
    for name in old:
        _touch(tmp_path / name, NOW)
    _touch(tmp_path / "latest.json", NOW)
    _touch(tmp_path / "notes.json", NOW)  # not a report: never touched
    _touch(tmp_path / "20261001T000000Z-aaaa.partial.json", NOW - 3600)  # young partial of another run
    _touch(tmp_path / "20260901T000000Z-bbbb.partial.json", NOW - 2 * 86400)  # stale partial
    notifier(tmp_path, keep=3).run_finished(make_report([make_vm(1)]))
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [
            old[3],
            old[4],
            f"{RUN}.json",
            "latest.json",
            "notes.json",
            "20261001T000000Z-aaaa.partial.json",
        ]
    )


def test_retention_unlimited(tmp_path: Path) -> None:
    for i in range(1, 6):
        _touch(tmp_path / f"2026100{i}T020000Z-000{i}.json", NOW)
    notifier(tmp_path, keep=0).run_finished(make_report([make_vm(1)]))
    assert len(list(tmp_path.glob("*.json"))) == 7


def test_stdout(tmp_path: Path) -> None:
    out = io.StringIO()
    report = make_report([make_vm(1)])
    notifier(tmp_path, out=out, stdout=True).run_finished(report)
    assert json.loads(out.getvalue())["run_id"] == RUN
    assert out.getvalue().startswith('{\n  "counts"')  # indent 2, sorted keys
    quiet = io.StringIO()
    notifier(tmp_path, out=quiet).run_finished(report)
    assert quiet.getvalue() == ""


def test_stdout_defaults_to_sys_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    JsonNotifier(JsonConfig(dir=tmp_path, stdout=True)).run_finished(make_report([make_vm(1)]))
    assert json.loads(capsys.readouterr().out)["run_id"] == RUN


def test_atomic_write_keeps_old_file_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / f"{RUN}.json"
    target.write_text("old")

    def boom(src: Any, dst: Any) -> None:
        raise OSError(28, "No space left on device", str(dst))

    monkeypatch.setattr(jsonfile.os, "replace", boom)
    with pytest.raises(PbvError) as ei:
        notifier(tmp_path).run_finished(make_report([make_vm(1)]))
    assert ei.value.code == "NOTIFY_FAIL"
    assert str(ei.value) == f"json: write report failed: {target}: No space left on device"
    assert target.read_text() == "old"
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name]  # temp file removed


def test_unwritable_dir_is_notify_fail(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    n = notifier(blocker / "reports")
    report = make_report([make_vm(1)])
    with pytest.raises(PbvError, match=r"^json: write partial failed: .*reports"):
        n.vm_finished(report.vms[0], report)
    with pytest.raises(PbvError, match=r"^json: write report failed: "):
        n.run_finished(report)
