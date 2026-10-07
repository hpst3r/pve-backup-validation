"""Root shell on the restore node: ``qm`` locally or over SSH (SPEC §1a).

PVE 9 restricts some operations to ``root@pam`` and an API token never is
``root@pam``: changing non-mapped ``hostpci``/``usb`` devices, real
``serial`` ports, ``args``/``hookscript``, and HMP ``screendump``. These go
through :class:`NodeShellRunner`, which runs ``qm`` as root either directly
(mode ``local``: pbv runs on the restore node) or with ``ssh`` (mode
``ssh``).

ssh joins its arguments into one string for the remote shell, so every remote
command is built with :func:`shlex.join` — values are never passed unquoted.

``screendump`` writes the image on the node's filesystem in ``remote_dir``.
In mode ``local`` the file is moved to its destination; in mode ``ssh`` it is
fetched with ``scp`` and then removed with ``ssh rm -f``. If the result is not
a PNG (old QEMU without ``-f png``) the capture is retried as PPM and
converted with ``pnmtopng`` or ``convert`` when one is installed.
:meth:`NodeShellRunner.screendump` never raises.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from pbv.config import NodeShellConfig
from pbv.core import ConfigError, PbvError

log = logging.getLogger("pbv.pve.nodeshell")

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PPM_MAGIC = b"P6"
NODE_SHELL_FAIL = "NODE_SHELL_FAIL"
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./-]*$")
_KEY = re.compile(r"^[a-z][a-z0-9_-]*$")
_STDERR_MAX = 200

Run = Callable[..., "subprocess.CompletedProcess[Any]"]


class CaptureError(Exception):
    """Internal: a screendump step failed; the message is the logged reason."""


class NodeShellRunner:
    """Implements :class:`pbv.core.NodeShell` (modes ``local`` and ``ssh``) plus ``probe``."""

    def __init__(
        self,
        cfg: NodeShellConfig,
        *,
        node: str,
        run: Run = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
        geteuid: Callable[[], int] = os.geteuid,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if cfg.mode not in ("local", "ssh"):
            raise ConfigError(f"node_shell.mode: NodeShellRunner needs 'local' or 'ssh', got {cfg.mode!r}")
        remote_dir = cfg.remote_dir.rstrip("/") or "/"
        # Interpolated into an HMP command line and a remote shell command.
        if not _SAFE_PATH.match(remote_dir):
            raise ConfigError("node_shell.remote_dir: must be an absolute path of [A-Za-z0-9_./-] characters")
        host = cfg.ssh_host or node
        if cfg.mode == "ssh" and not host:
            raise ConfigError('node_shell.ssh_host: required when mode = "ssh"')
        if cfg.timeout_s <= 0:
            raise ConfigError("node_shell.timeout_s: must be > 0")
        self.cfg = cfg
        self.node = node
        self.mode = cfg.mode
        self.remote_dir = remote_dir
        self.host = host
        self.timeout_s = cfg.timeout_s
        self._run = run
        self._which = which
        self._geteuid = geteuid
        self._wall_clock = wall_clock

    @classmethod
    def from_config(cls, cfg: NodeShellConfig, *, node: str, **kw: Any) -> NodeShellRunner | None:
        """Build from ``[node_shell]``; returns None when ``mode == "off"``."""
        if cfg.mode == "off":
            return None
        return cls(cfg, node=node, **kw)

    def __repr__(self) -> str:
        where = f"{self._target()}:{self.cfg.ssh_port}" if self.mode == "ssh" else self.node
        return f"NodeShellRunner(mode={self.mode!r}, node={where!r})"

    # ── public ─────────────────────────────────────────────────────────────────
    def probe(self) -> str:
        """Check the shell is usable; returns a summary or raises NODE_SHELL_FAIL."""
        if self.mode == "local":
            if self._geteuid() != 0:
                raise PbvError(
                    "pbv must run as root on the restore node for node_shell.mode = local", code=NODE_SHELL_FAIL
                )
            if not self._which("qm"):
                raise PbvError("qm not found: is this a PVE node?", code=NODE_SHELL_FAIL)
            return f"local root on {self.node or 'this node'}: ok"
        self._qm(["qm", "list"], f"ssh {self._target()}")
        return f"ssh {self._target()}: ok"

    def qm_set(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str]) -> None:
        """Run ``qm set <vmid> --k v ... --delete k1,k2``; raises NODE_SHELL_FAIL."""
        if not isinstance(vmid, int) or isinstance(vmid, bool):
            raise PbvError(f"node shell: vmid must be an int, got {type(vmid).__name__}", code=NODE_SHELL_FAIL)
        if not set_ and not delete:
            return
        for key in [*set_, *delete]:
            if not isinstance(key, str) or not _KEY.match(key):
                raise PbvError(f"node shell: refusing invalid config key {key!r}", code=NODE_SHELL_FAIL)
        for key, value in set_.items():
            if not isinstance(value, str):
                raise PbvError(f"node shell: value for {key} must be a string", code=NODE_SHELL_FAIL)
        argv = ["qm", "set", str(vmid)]
        for key in sorted(set_):
            argv += [f"--{key}", set_[key]]
        if delete:
            argv += ["--delete", ",".join(sorted(delete))]
        self._qm(argv, f"qm set {vmid}")
        log.info("NODE_SHELL_QM_SET vmid=%s set=%s delete=%s", vmid, ",".join(sorted(set_)), ",".join(sorted(delete)))

    def screendump(self, vmid: int, dest: Path) -> Path | None:
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
        except Exception as e:  # boundary: screendump must never raise
            log.debug("screenshot traceback", exc_info=True)
            log.warning("SCREENSHOT_FAIL vmid=%s reason=%s: %s", vmid, type(e).__name__, e)
        return None

    # ── screendump steps ───────────────────────────────────────────────────────
    def _grab(self, vmid: int, filename: str, local: Path, *, as_png: bool) -> None:
        """screendump into ``remote_dir/filename`` and bring it to ``local``."""
        remote = f"{self.remote_dir}/{filename}"
        hmp = f"screendump {remote}" + (" -f png" if as_png else "") + "\n"
        monitor = ["qm", "monitor", str(vmid)]
        if self.mode == "local":
            Path(self.remote_dir).mkdir(parents=True, exist_ok=True)
        try:
            proc = self._qm(monitor, f"qm monitor {vmid}", input=hmp.encode(), mkdir=self.remote_dir)
        except PbvError as e:
            raise CaptureError(str(e)) from None
        out = _text(proc.stdout).strip()
        if out:
            log.debug("SCREENDUMP_OUTPUT vmid=%s output=%s", vmid, out[-_STDERR_MAX:])
        if self.mode == "local":
            src = Path(remote)
            if not src.exists():
                raise CaptureError(f"{remote} was not created ({_last_line(out) or 'no monitor output'})")
            shutil.move(str(src), str(local))
            return
        try:
            self._exec(["scp", *self._ssh_opts("-P"), f"{self._scp_host()}:{remote}", str(local)], "scp")
        finally:
            self._remove_remote(remote)

    def _remove_remote(self, remote: str) -> None:
        try:
            self._qm(["rm", "-f", "--", remote], "ssh rm")
        except PbvError as e:
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
    def _qm(
        self, argv: list[str], what: str, *, input: bytes | None = None, mkdir: str | None = None
    ) -> subprocess.CompletedProcess[Any]:
        """Run ``argv`` on the node (directly or via ssh); raises NODE_SHELL_FAIL."""
        full = self.command(argv, mkdir=mkdir)
        kw: dict[str, Any] = {"capture_output": True, "timeout": self.timeout_s, "check": False}
        if input is not None:
            kw["input"] = input
        try:
            proc = self._run(full, **kw)
        except subprocess.TimeoutExpired:
            raise PbvError(f"node shell: {what} timed out after {self.timeout_s}s", code=NODE_SHELL_FAIL) from None
        except OSError as e:
            raise PbvError(f"node shell: {what} could not run: {e}", code=NODE_SHELL_FAIL) from None
        if proc.returncode != 0:
            tail = _last_line(_text(proc.stderr)) or "no stderr"
            raise PbvError(f"node shell: {what} failed (exit {proc.returncode}): {tail}", code=NODE_SHELL_FAIL)
        return proc

    def command(self, argv: list[str], *, mkdir: str | None = None) -> list[str]:
        """The local argv that runs ``argv`` on the node (``mkdir`` only applies to ssh)."""
        if self.mode == "local":
            return list(argv)
        remote = shlex.join(argv)
        if mkdir:
            remote = f"{shlex.join(['mkdir', '-p', mkdir])} && {remote}"
        return ["ssh", *self._ssh_opts("-p"), self._target(), "--", remote]

    def _exec(self, argv: list[str], what: str, *, stdout: Any = subprocess.PIPE) -> None:
        """Run a local helper (scp, converters); raises CaptureError."""
        try:
            proc = self._run(argv, stdout=stdout, stderr=subprocess.PIPE, timeout=self.timeout_s, check=False)
        except subprocess.TimeoutExpired:
            raise CaptureError(f"{what} timed out after {self.timeout_s}s") from None
        except OSError as e:
            raise CaptureError(f"{what} could not run: {e}") from None
        if proc.returncode != 0:
            raise CaptureError(f"{what} exited {proc.returncode}: {_last_line(_text(proc.stderr)) or 'no stderr'}")

    def _target(self) -> str:
        return f"{self.cfg.ssh_user}@{self.host}" if self.cfg.ssh_user else self.host

    def _scp_host(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.cfg.ssh_user}@{host}" if self.cfg.ssh_user else host

    def _ssh_opts(self, port_flag: str) -> list[str]:
        opts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]
        opts += [port_flag, str(self.cfg.ssh_port)]
        if self.cfg.ssh_key_file:
            opts += ["-i", self.cfg.ssh_key_file, "-o", "IdentitiesOnly=yes"]
        if self.cfg.ssh_known_hosts_file:
            opts += ["-o", f"UserKnownHostsFile={self.cfg.ssh_known_hosts_file}"]
        return opts


def _text(data: Any) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data or "")


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:_STDERR_MAX] if lines else ""


def _magic(path: Path, magic: bytes) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(magic)) == magic
    except OSError:
        return False
