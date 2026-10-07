"""ConsoleCapture against FakePve with a fake ``run`` (no real ssh/scp/converters)."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

import pytest

from pbv.config import ScreenshotConfig
from pbv.core import ApiError, ConfigError, ConsoleCapturer
from pbv.pve import ConsoleCapture
from pbv.pve.console import PNG_MAGIC
from pbv.testing.fakes import FakePve

VMID = 900105
TS = 1760000000.0


class ScreenPve(FakePve):
    """FakePve whose ``screendump`` writes a file into ``fs_root`` + path.

    ``png_ok``: ``-f png`` produces a PNG; otherwise QEMU complains and writes nothing.
    """

    def __init__(self, fs_root: Path | None = None, *, png_ok: bool = True) -> None:
        super().__init__()
        self.fs_root = fs_root
        self.png_ok = png_ok
        self.add_vm(VMID, status="running")

    def monitor(self, vmid: int, command: str) -> str:
        super().monitor(vmid, command)
        parts = command.split()
        assert parts[0] == "screendump"
        target = Path(str(self.fs_root) + parts[1]) if self.fs_root else None
        if parts[2:] == ["-f", "png"]:
            if not self.png_ok:
                return "screendump: invalid option -f\n"
            if target:
                target.write_bytes(PNG_MAGIC + b"img")
        elif target:
            target.write_bytes(b"P6\n1 1\n255\n\x00\x00\x00")
        return ""


class FakeRun:
    """Records argv; scp copies from ``remote_root``; converters write a PNG."""

    def __init__(self, remote_root: Path | None = None, fail: dict[str, Any] | None = None) -> None:
        self.remote_root = remote_root
        self.fail = fail or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        err = self.fail.get(tool)
        if isinstance(err, BaseException):
            raise err
        if err is not None:
            return subprocess.CompletedProcess(argv, err, b"", b"Permission denied (publickey)")
        assert kw["timeout"] > 0
        if tool == "scp" and self.remote_root:
            src = Path(str(self.remote_root) + argv[-2].split(":", 1)[1])
            Path(argv[-1]).write_bytes(src.read_bytes())
        elif tool == "pnmtopng":
            kw["stdout"].write(PNG_MAGIC + b"converted")
        elif tool == "convert":
            Path(argv[-1]).write_bytes(PNG_MAGIC + b"converted")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def _which(available: set[str]) -> Any:
    return lambda name: f"/usr/bin/{name}" if name in available else None


def local(tmp_path: Path, api: FakePve, **kw: Any) -> ConsoleCapture:
    kw.setdefault("run", FakeRun())
    return ConsoleCapture(api, mode="local", remote_dir=str(tmp_path / "remote"), wall_clock=lambda: TS, **kw)


def test_protocol(tmp_path: Path) -> None:
    assert isinstance(local(tmp_path, ScreenPve()), ConsoleCapturer)


def test_local_png(tmp_path: Path) -> None:
    api = ScreenPve(Path("/"))
    out = local(tmp_path, api).capture(VMID, tmp_path / "work" / "boot.v1")
    assert out == tmp_path / "work" / "boot.v1.png"
    assert out.read_bytes().startswith(PNG_MAGIC)
    remote = tmp_path / "remote" / f"pbv-{VMID}-{int(TS)}.png"
    assert api.monitor_log == [(VMID, f"screendump {remote} -f png")]
    assert not remote.exists()  # moved, not copied


def test_local_ppm_fallback_with_pnmtopng(tmp_path: Path) -> None:
    api = ScreenPve(Path("/"), png_ok=False)
    run = FakeRun()
    out = local(tmp_path, api, run=run, which=_which({"pnmtopng", "convert"})).capture(VMID, tmp_path / "shot")
    assert out == tmp_path / "shot.png"
    assert out.read_bytes() == PNG_MAGIC + b"converted"
    assert api.monitor_log[1][1].endswith(".ppm")
    assert run.calls == [["/usr/bin/pnmtopng", str(tmp_path / "shot.ppm")]]
    assert not (tmp_path / "shot.ppm").exists()


def test_local_ppm_fallback_with_convert(tmp_path: Path) -> None:
    api = ScreenPve(Path("/"), png_ok=False)
    run = FakeRun()
    out = local(tmp_path, api, run=run, which=_which({"convert"})).capture(VMID, tmp_path / "shot")
    assert out is not None
    assert run.calls[0][0] == "/usr/bin/convert"


def test_ppm_without_converter_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    api = ScreenPve(Path("/"), png_ok=False)
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert local(tmp_path, api, which=_which(set())).capture(VMID, tmp_path / "shot") is None
    assert "neither pnmtopng nor convert" in caplog.text
    assert (tmp_path / "shot.ppm").exists()  # kept for diagnosis


def test_converter_failure_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    api = ScreenPve(Path("/"), png_ok=False)
    run = FakeRun(fail={"pnmtopng": 1})
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert local(tmp_path, api, run=run, which=_which({"pnmtopng"})).capture(VMID, tmp_path / "s") is None
    assert "pnmtopng exited 1" in caplog.text


def test_nothing_written_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    api = ScreenPve(None)  # monitor succeeds but writes no file
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert local(tmp_path, api).capture(VMID, tmp_path / "s") is None
    assert "SCREENSHOT_FAIL" in caplog.text
    assert "was not created" in caplog.text


def test_monitor_api_error_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    api = ScreenPve(Path("/"))
    api.vms[VMID].status = "stopped"
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert local(tmp_path, api).capture(VMID, tmp_path / "s") is None
    assert "is not running" in caplog.text


def test_unexpected_exception_never_raises(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    class Boom(ScreenPve):
        def monitor(self, vmid: int, command: str) -> str:
            raise RuntimeError("kaboom")

    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert local(tmp_path, Boom()).capture(VMID, tmp_path / "s") is None
    assert "kaboom" in caplog.text


def test_unwritable_dest_never_raises(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert local(tmp_path, ScreenPve(Path("/"))).capture(VMID, blocker / "sub" / "s") is None


def ssh(tmp_path: Path, api: FakePve, run: FakeRun, **kw: Any) -> ConsoleCapture:
    return ConsoleCapture(
        api,
        mode="ssh",
        remote_dir="/var/lib/pbv/screendump",
        ssh_host="restore01.example",
        ssh_user="pbv",
        ssh_port=2222,
        ssh_key_file="/etc/pbv/id_ed25519",
        ssh_known_hosts_file="/etc/pbv/known_hosts",
        run=run,
        wall_clock=lambda: TS,
        **kw,
    )


@pytest.fixture
def remote_root(tmp_path: Path) -> Path:
    root = tmp_path / "node"
    (root / "var/lib/pbv/screendump").mkdir(parents=True)
    return root


def test_ssh_png(tmp_path: Path, remote_root: Path) -> None:
    api = ScreenPve(remote_root)
    run = FakeRun(remote_root)
    out = ssh(tmp_path, api, run).capture(VMID, tmp_path / "w" / "s")
    assert out == tmp_path / "w" / "s.png"
    assert out.read_bytes().startswith(PNG_MAGIC)
    remote = f"/var/lib/pbv/screendump/pbv-{VMID}-{int(TS)}.png"
    opts = [
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=/etc/pbv/known_hosts", "-i", "/etc/pbv/id_ed25519",
    ]  # fmt: skip
    assert run.calls == [
        ["scp", "-P", "2222", *opts, f"pbv@restore01.example:{remote}", str(out)],
        ["ssh", "-p", "2222", *opts, "pbv@restore01.example", f"rm -f -- {remote}"],
    ]


def test_ssh_ppm_fallback(tmp_path: Path, remote_root: Path) -> None:
    api = ScreenPve(remote_root, png_ok=False)
    run = FakeRun(remote_root)
    out = ssh(tmp_path, api, run, which=_which({"pnmtopng"})).capture(VMID, tmp_path / "s")
    assert out is not None
    assert out.read_bytes() == PNG_MAGIC + b"converted"
    tools = [Path(c[0]).name for c in run.calls]
    # png attempt: scp fails (no file) → rm; ppm attempt: scp → rm → convert
    assert tools == ["scp", "ssh", "scp", "ssh", "pnmtopng"]


def test_ssh_scp_failure_returns_none_and_still_removes(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(fail={"scp": 1})
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert ssh(tmp_path, ScreenPve(None), run).capture(VMID, tmp_path / "s") is None
    assert "scp exited 1" in caplog.text
    assert "Permission denied" in caplog.text
    assert [Path(c[0]).name for c in run.calls].count("ssh") == 2


@pytest.mark.parametrize("err", [FileNotFoundError("scp"), subprocess.TimeoutExpired("scp", 60)])
def test_ssh_tool_missing_or_timeout(tmp_path: Path, err: BaseException, caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(fail={"scp": err, "ssh": err})
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        assert ssh(tmp_path, ScreenPve(None), run).capture(VMID, tmp_path / "s") is None
    assert "SCREENSHOT_FAIL" in caplog.text
    assert "SCREENSHOT_REMOTE_CLEANUP_FAIL" in caplog.text


def test_ssh_without_optional_files(tmp_path: Path, remote_root: Path) -> None:
    run = FakeRun(remote_root)
    cap = ConsoleCapture(
        ScreenPve(remote_root), mode="ssh", remote_dir="/var/lib/pbv/screendump", ssh_host="h", run=run
    )
    assert cap.capture(VMID, tmp_path / "s") is not None
    assert "-i" not in run.calls[0]
    assert not any(a.startswith("UserKnownHostsFile") for a in run.calls[0])
    assert run.calls[0][-2].startswith("root@h:")


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"mode": "vnc", "remote_dir": "/tmp"}, "mode"),
        ({"mode": "local", "remote_dir": "/tmp/a b"}, "remote_dir"),
        ({"mode": "local", "remote_dir": "/tmp/$(id)"}, "remote_dir"),
        ({"mode": "local", "remote_dir": "relative"}, "remote_dir"),
        ({"mode": "ssh", "remote_dir": "/tmp"}, "ssh_host"),
    ],
)
def test_constructor_validation(kw: dict[str, Any], match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        ConsoleCapture(FakePve(), **kw)


def test_from_config() -> None:
    api = FakePve()
    assert ConsoleCapture.from_config(api, ScreenshotConfig(mode="off")) is None
    cap = ConsoleCapture.from_config(api, ScreenshotConfig(mode="ssh", ssh_host="n1", ssh_port=2200))
    assert isinstance(cap, ConsoleCapture)
    assert (cap.mode, cap.ssh_host, cap.ssh_port, cap.remote_dir) == ("ssh", "n1", 2200, "/var/lib/pbv/screendump")


def test_api_error_type_is_not_leaked(tmp_path: Path) -> None:
    class Err(ScreenPve):
        def monitor(self, vmid: int, command: str) -> str:
            raise ApiError("VM.Monitor permission missing", status=403)

    assert local(tmp_path, Err()).capture(VMID, tmp_path / "s") is None
