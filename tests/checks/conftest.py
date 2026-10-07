"""Shared fixtures for pbv.checks tests: fake clock, contexts, engine factory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pbv.checks import CheckEngine
from pbv.core import CheckContext, CheckSpec, OsFamily


class FakeClock:
    """Monotonic clock advanced only by ``sleep`` (and explicit ``advance``)."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s

    def advance(self, s: float) -> None:
        self.now += s


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_ctx(tmp_path: Path, os: OsFamily = OsFamily.LINUX, ips: tuple[str, ...] = ("10.99.0.5", "fd00::5")):
    return CheckContext(
        run_id="20261007T020000Z-ab12",
        target_node="restore01",
        vmid=105,
        temp_vmid=900105,
        vm_name="web01",
        os=os,
        guest_ips=ips,
        work_dir=tmp_path / "work" / "105",
        config_dir=tmp_path,
    )


@pytest.fixture
def ctx(tmp_path: Path) -> CheckContext:
    return make_ctx(tmp_path)


@pytest.fixture
def wctx(tmp_path: Path) -> CheckContext:
    return make_ctx(tmp_path, OsFamily.WINDOWS)


@pytest.fixture
def engine(tmp_path: Path, clock: FakeClock) -> CheckEngine:
    return CheckEngine(tmp_path, sleep=clock.sleep, clock=clock)


def spec(ctype: str, name: str = "", *, critical: bool = True, wait_s: int = 0, timeout_s: int = 30, **params: Any):
    """CheckSpec with the config loader's defaults for ``ctype`` filled in."""
    from pbv.config import CHECK_TYPES

    full: dict[str, Any] = {}
    for key, (_typ, _req, default) in CHECK_TYPES.get(ctype, {}).items():
        full[key] = list(default) if isinstance(default, list) else default
    full.update(params)
    only = {"systemd": OsFamily.LINUX, "log_scan": OsFamily.LINUX, "windows_service": OsFamily.WINDOWS}.get(ctype)
    return CheckSpec(
        type=ctype,
        name=name or f"{ctype}:x",
        params=full,
        critical=critical,
        timeout_s=timeout_s,
        wait_s=wait_s,
        only_os=only,
    )
