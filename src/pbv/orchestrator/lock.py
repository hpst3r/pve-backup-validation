"""Single-instance run lock (SPEC §4 "Lock")."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from types import TracebackType

from pbv.core import PbvError


class RunLock:
    """``fcntl.flock(LOCK_EX | LOCK_NB)`` on ``path``, as a context manager.

    Raises ``PbvError(code="LOCKED")`` when another process (or another open
    of the same file) holds the lock, and ``PbvError(code="LOCK_ERROR")`` when
    the lock file cannot be opened.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError as exc:
            raise PbvError(f"cannot open lock file {self.path}: {exc.strerror}", code="LOCK_ERROR") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise PbvError("another pbv run is in progress", code="LOCKED") from None
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.release()
