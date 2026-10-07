"""A17 run lock, StopFlag signal handling, run ids."""

from __future__ import annotations

import os
import re
import signal
from datetime import UTC, datetime, timedelta, timezone

import pytest

from pbv.core import PbvError
from pbv.orchestrator import RunLock, StopFlag, new_run_id
from pbv.testing.fakes import FakePve

from .conftest import Env, add_backup


def test_lock_held_blocks_second_run_without_api_calls(env: Env, tmp_path):
    path = tmp_path / "run" / "pbv.lock"
    add_backup(env.pve, 105)
    pve = FakePve()
    with RunLock(path) as first:
        assert first.held
        with pytest.raises(PbvError) as ei, RunLock(path):
            env.runner(env.cfg()).run()  # never reached
        assert ei.value.code == "LOCKED" and str(ei.value) == "another pbv run is in progress"
    assert env.pve.calls == [] and pve.calls == []
    assert not first.held
    with RunLock(path):  # released → can be taken again
        pass
    assert path.read_text().strip() == str(os.getpid())


def test_lock_unopenable(tmp_path):
    blocker = tmp_path / "f"
    blocker.write_text("")
    with pytest.raises(PbvError) as ei:
        RunLock(blocker / "pbv.lock").acquire()
    assert ei.value.code == "LOCK_ERROR"


def test_release_is_idempotent(tmp_path):
    lock = RunLock(tmp_path / "l")
    lock.release()
    lock.acquire()
    lock.release()
    lock.release()


def test_stop_flag_sets_on_signal_and_restores_handlers():
    before_int, before_term = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    flag = StopFlag()
    with flag:
        assert not flag()
        os.kill(os.getpid(), signal.SIGTERM)
        assert flag() and flag.count == 1
        os.kill(os.getpid(), signal.SIGINT)  # second signal: logged, never raises
        assert flag.count == 2
    assert signal.getsignal(signal.SIGINT) is before_int and signal.getsignal(signal.SIGTERM) is before_term


def test_stop_flag_in_cleanup_records_only(caplog):
    flag = StopFlag()
    flag.install()
    try:
        flag.in_cleanup = True
        os.kill(os.getpid(), signal.SIGINT)
        os.kill(os.getpid(), signal.SIGINT)
    finally:
        flag.uninstall()
    assert flag.count == 2 and flag()
    assert caplog.text.count("SIGNAL_DEFERRED") == 2


def test_new_run_id_format():
    rid = new_run_id(datetime(2026, 10, 7, 4, 0, 0, tzinfo=timezone(timedelta(hours=2))))
    assert re.fullmatch(r"20261007T020000Z-[0-9a-f]{4}", rid)
    assert re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{4}", new_run_id())
    assert new_run_id(datetime(2026, 1, 1, tzinfo=UTC)).startswith("20260101T000000Z-")
