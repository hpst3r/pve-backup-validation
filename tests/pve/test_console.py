"""ConsoleCapture: a thin ConsoleCapturer adapter over a NodeShell."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from pbv.config import ScreenshotConfig
from pbv.core import ConsoleCapturer
from pbv.pve import ConsoleCapture
from pbv.testing.fakes import FakeNodeShell

VMID = 900105


class RaisingShell:
    """A misbehaving NodeShell whose screendump raises."""

    def qm_set(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str]) -> None:
        raise AssertionError("not used")

    def screendump(self, vmid: int, dest: Path) -> Path | None:
        raise RuntimeError("shell exploded")


def test_protocol() -> None:
    assert isinstance(ConsoleCapture(FakeNodeShell()), ConsoleCapturer)


def test_capture_delegates_to_screendump(tmp_path: Path) -> None:
    shell = FakeNodeShell()
    out = ConsoleCapture(shell).capture(VMID, tmp_path / "boot")
    assert shell.screendumps == [VMID]
    assert out is not None
    assert out.exists()


def test_capture_returns_none_on_shell_failure(tmp_path: Path) -> None:
    assert ConsoleCapture(FakeNodeShell(fail=True)).capture(VMID, tmp_path / "boot") is None


def test_capture_never_raises(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert ConsoleCapture(RaisingShell()).capture(VMID, tmp_path / "boot") is None
    assert "SCREENSHOT_FAIL" in caplog.text
    assert "RuntimeError: shell exploded" in caplog.text


def test_from_config() -> None:
    shell = FakeNodeShell()
    assert ConsoleCapture.from_config(shell, ScreenshotConfig(enabled=False)) is None
    assert ConsoleCapture.from_config(None, ScreenshotConfig(enabled=True)) is None
    cap = ConsoleCapture.from_config(shell, ScreenshotConfig(enabled=True, when="always"))
    assert isinstance(cap, ConsoleCapture)
    assert cap.shell is shell
