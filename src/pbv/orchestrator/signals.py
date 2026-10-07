"""SIGINT/SIGTERM handling (SPEC §4 "Signals").

Signals only set a flag; the orchestrator polls it (``should_stop``) and
raises :class:`pbv.core.InterruptedRun` at the next poll. While
``in_cleanup`` is True, signals are counted and logged but never interrupt.
"""

from __future__ import annotations

import logging
import signal
from types import FrameType, TracebackType
from typing import Any

log = logging.getLogger("pbv.orchestrator")

_SIGNALS = (signal.SIGINT, signal.SIGTERM)


class StopFlag:
    """Callable stop flag set by SIGINT/SIGTERM once :meth:`install` ran."""

    def __init__(self) -> None:
        self.stopped = False
        self.count = 0
        self.in_cleanup = False
        self._previous: dict[int, Any] = {}

    def install(self) -> None:
        """Route SIGINT/SIGTERM to this flag (main thread only)."""
        for sig in _SIGNALS:
            if sig not in self._previous:
                self._previous[sig] = signal.signal(sig, self._handle)

    def uninstall(self) -> None:
        """Restore the handlers that were active before :meth:`install`."""
        for sig, prev in self._previous.items():
            signal.signal(sig, prev)
        self._previous.clear()

    def set(self) -> None:
        self.stopped = True

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        self.count += 1
        name = signal.Signals(signum).name
        if self.in_cleanup:
            log.warning("SIGNAL_DEFERRED signal=%s count=%d (cleanup finishes first)", name, self.count)
        elif self.stopped:
            log.warning("SIGNAL_IGNORED signal=%s count=%d (already stopping)", name, self.count)
        else:
            log.warning("SIGNAL_RECEIVED signal=%s (stopping after the current step; cleanup still runs)", name)
        self.stopped = True

    def __call__(self) -> bool:
        return self.stopped

    def __enter__(self) -> StopFlag:
        self.install()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.uninstall()
