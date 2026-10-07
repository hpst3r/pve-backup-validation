"""VGA console screenshots (SPEC §1a, §9).

HMP ``screendump`` is root-only in PVE 9, so the capture itself lives in
:meth:`pbv.core.NodeShell.screendump` (see :mod:`pbv.pve.nodeshell`);
:class:`ConsoleCapture` adapts a node shell to :class:`pbv.core.ConsoleCapturer`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from pbv.config import ScreenshotConfig
from pbv.core import NodeShell

log = logging.getLogger("pbv.pve.console")


class ConsoleCapture:
    """Implements :class:`pbv.core.ConsoleCapturer` on top of a :class:`pbv.core.NodeShell`."""

    def __init__(self, shell: NodeShell) -> None:
        self.shell = shell

    @classmethod
    def from_config(cls, shell: NodeShell | None, shot: ScreenshotConfig) -> ConsoleCapture | None:
        """Returns None unless ``shot.enabled`` and a node shell is configured."""
        if not shot.enabled or shell is None:
            return None
        return cls(shell)

    def capture(self, vmid: int, dest: Path) -> Path | None:
        """Write ``<dest>.png``; returns its path, or None. Never raises."""
        try:
            return self.shell.screendump(vmid, dest)
        except Exception as e:  # boundary: NodeShell.screendump must not raise, but capture never does
            log.debug("screenshot traceback", exc_info=True)
            log.warning("SCREENSHOT_FAIL vmid=%s reason=%s: %s", vmid, type(e).__name__, e)
            return None
