"""VGA console screenshots via the QEMU monitor (``screendump``).

``screendump`` writes the image on the PVE node's filesystem, in
``remote_dir``. In mode ``local`` pbv runs on that node, so the file is
moved to its destination (``remote_dir`` is created with ``mkdir -p``). In
mode ``ssh`` the file is fetched with ``scp`` and then removed with ``ssh rm
-f``; ``remote_dir`` is assumed to already exist on the node.

If the result is not a PNG (old QEMU without ``-f png``) the capture is
retried as PPM and converted with ``pnmtopng`` or ``convert`` when one of
them is installed. :meth:`ConsoleCapture.capture` never raises.
"""

from __future__ import annotations

import logging
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pbv.config import ScreenshotConfig
from pbv.core import ConfigError, PveApi

log = logging.getLogger("pbv.pve.console")

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PPM_MAGIC = b"P6"
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./-]*$")
_SUBPROCESS_TIMEOUT_S = 60


class CaptureError(Exception):
    """Internal: a capture step failed; the message is the logged reason."""


class ConsoleCapture:
    """Implements :class:`pbv.core.ConsoleCapturer` (modes ``local`` and ``ssh``)."""

    def __init__(
        self,
        api: PveApi,
        *,
        mode: str,
        remote_dir: str,
        ssh_host: str = "",
        ssh_user: str = "root",
        ssh_port: int = 22,
        ssh_key_file: str = "",
        ssh_known_hosts_file: str = "",
        run: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if mode not in ("local", "ssh"):
            raise ConfigError(f"screenshot.mode: unsupported capture mode {mode!r}")
        remote_dir = remote_dir.rstrip("/") or "/"
        # The path is interpolated into an HMP command line and a remote shell command.
        if not _SAFE_PATH.match(remote_dir):
            raise ConfigError("screenshot.remote_dir: must be an absolute path of [A-Za-z0-9_./-] characters")
        if mode == "ssh" and not ssh_host:
            raise ConfigError('screenshot.ssh_host: required when mode = "ssh"')
        self.api = api
        self.mode = mode
        self.remote_dir = remote_dir
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        self.ssh_key_file = ssh_key_file
        self.ssh_known_hosts_file = ssh_known_hosts_file
        self._run = run
        self._which = which
        self._wall_clock = wall_clock

    @classmethod
    def from_config(cls, api: PveApi, shot: ScreenshotConfig, **kw: Any) -> ConsoleCapture | None:
        """Build from ``[screenshot]``; returns None when ``mode == "off"``."""
        if shot.mode == "off":
            return None
        return cls(
            api,
            mode=shot.mode,
            remote_dir=shot.remote_dir,
            ssh_host=shot.ssh_host,
            ssh_user=shot.ssh_user,
            ssh_port=shot.ssh_port,
            ssh_key_file=shot.ssh_key_file,
            ssh_known_hosts_file=shot.ssh_known_hosts_file,
            **kw,
        )

    # ── public ─────────────────────────────────────────────────────────────────
    def capture(self, vmid: int, dest: Path) -> Path | None:
        """Write ``<dest>.png``; returns its path, or None (reason logged at WARNING)."""
        png = dest.with_name(dest.name + ".png")
        try:
            png.parent.mkdir(parents=True, exist_ok=True)
            name = f"pbv-{vmid}-{int(self._wall_clock())}"
            try:
                self._grab(vmid, f"{name}.png", png, as_png=True)
                if _magic(png, PNG_MAGIC):
                    log.info("SCREENSHOT_OK vmid=%s file=%s", vmid, png)
                    return png
                reason = "screendump -f png produced no PNG"
            except CaptureError as e:
                reason = str(e)
            log.info("SCREENSHOT_PNG_FAIL vmid=%s reason=%s; retrying as PPM", vmid, reason)
            png.unlink(missing_ok=True)
            ppm = dest.with_name(dest.name + ".ppm")
            self._grab(vmid, f"{name}.ppm", ppm, as_png=False)
            if not _magic(ppm, PPM_MAGIC):
                raise CaptureError("screendump produced neither PNG nor PPM")
            self._convert(ppm, png)
            ppm.unlink(missing_ok=True)
            log.info("SCREENSHOT_OK vmid=%s file=%s (converted from PPM)", vmid, png)
            return png
        except CaptureError as e:
            log.warning("SCREENSHOT_FAIL vmid=%s reason=%s", vmid, e)
        except Exception as e:  # boundary: capture must never raise
            log.debug("screenshot traceback", exc_info=True)
            log.warning("SCREENSHOT_FAIL vmid=%s reason=%s: %s", vmid, type(e).__name__, e)
        return None

    # ── steps ──────────────────────────────────────────────────────────────────
    def _grab(self, vmid: int, filename: str, local: Path, *, as_png: bool) -> None:
        """screendump into ``remote_dir/filename`` and bring it to ``local``."""
        remote = f"{self.remote_dir}/{filename}"
        if self.mode == "local":
            Path(self.remote_dir).mkdir(parents=True, exist_ok=True)
        command = f"screendump {remote}" + (" -f png" if as_png else "")
        try:
            out = self.api.monitor(vmid, command)
        except Exception as e:  # any PveApi implementation; reported as the capture reason
            log.debug("monitor traceback", exc_info=True)
            raise CaptureError(f"monitor {command!r}: {e}") from None
        if out.strip():
            log.debug("SCREENDUMP_OUTPUT vmid=%s output=%s", vmid, out.strip()[:200])
        if self.mode == "local":
            src = Path(remote)
            if not src.exists():
                raise CaptureError(f"{remote} was not created ({out.strip()[:200] or 'no monitor output'})")
            shutil.move(str(src), str(local))
            return
        try:
            self._exec(["scp", *self._ssh_opts("-P"), f"{self._target()}:{remote}", str(local)], "scp")
        finally:
            self._remove_remote(remote)

    def _remove_remote(self, remote: str) -> None:
        try:
            self._exec(["ssh", *self._ssh_opts("-p"), self._target(), "rm -f -- " + shlex.quote(remote)], "ssh rm")
        except CaptureError as e:
            log.warning("SCREENSHOT_REMOTE_CLEANUP_FAIL file=%s reason=%s", remote, e)

    def _convert(self, ppm: Path, png: Path) -> None:
        pnmtopng = self._which("pnmtopng")
        if pnmtopng:
            with png.open("wb") as fh:
                self._exec([pnmtopng, str(ppm)], "pnmtopng", stdout=fh)
        else:
            convert = self._which("convert")
            if not convert:
                raise CaptureError(f"got PPM but neither pnmtopng nor convert is installed (kept {ppm})")
            self._exec([convert, str(ppm), str(png)], "convert")
        if not _magic(png, PNG_MAGIC):
            png.unlink(missing_ok=True)
            raise CaptureError(f"PPM conversion produced no PNG (kept {ppm})")

    # ── subprocess helpers ─────────────────────────────────────────────────────
    def _target(self) -> str:
        return f"{self.ssh_user}@{self.ssh_host}" if self.ssh_user else self.ssh_host

    def _ssh_opts(self, port_flag: str) -> list[str]:
        opts = [port_flag, str(self.ssh_port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
        if self.ssh_known_hosts_file:
            opts += ["-o", f"UserKnownHostsFile={self.ssh_known_hosts_file}"]
        if self.ssh_key_file:
            opts += ["-i", self.ssh_key_file]
        return opts

    def _exec(self, argv: list[str], what: str, *, stdout: Any = subprocess.PIPE) -> None:
        try:
            proc = self._run(argv, stdout=stdout, stderr=subprocess.PIPE, timeout=_SUBPROCESS_TIMEOUT_S, check=False)
        except subprocess.TimeoutExpired:
            raise CaptureError(f"{what} timed out after {_SUBPROCESS_TIMEOUT_S}s") from None
        except OSError as e:
            raise CaptureError(f"{what} could not run: {e}") from None
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace") if isinstance(proc.stderr, bytes) else str(proc.stderr or "")
            raise CaptureError(f"{what} exited {proc.returncode}: {err.strip()[:300]}")


def _magic(path: Path, magic: bytes) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(magic)) == magic
    except OSError:
        return False
