"""JSON report notifier: atomic report files, ``latest.json``, partials, retention."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from pbv.config import JsonConfig
from pbv.core import NotifyWhen, RunReport, VmResult, report_to_dict
from pbv.notify.base import BaseNotifier, notify_error
from pbv.notify.render import should_send_run

log = logging.getLogger("pbv.notify")

FILE_MODE = 0o640
DIR_MODE = 0o750
LATEST = "latest.json"
PARTIAL_SUFFIX = ".partial.json"
STALE_PARTIAL_S = 24 * 3600
_REPORT_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]+\.json$")
_PARTIAL_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]+\.partial\.json$")


def dump_report(report: RunReport) -> str:
    """The canonical JSON text of a report (stable key order, UTF-8)."""
    return json.dumps(report_to_dict(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def atomic_write(path: Path, text: str, mode: int = FILE_MODE) -> None:
    """Write ``text`` to ``path`` via a temp file in the same dir + ``os.replace``."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class JsonNotifier(BaseNotifier):
    """Writes ``{dir}/{run_id}.json`` (+ ``latest.json``) per SPEC §6/§7.

    ``vm_finished`` rewrites ``{run_id}.partial.json`` (unless ``when`` is
    ``never``) so a crashed run leaves its progress behind; ``run_finished``
    writes the final report when ``when`` matches, always removes the partial,
    and applies retention. ``stdout`` (default ``sys.stdout`` at call time)
    receives the JSON when ``cfg.stdout`` is set. ``clock`` is wall time.
    """

    name = "json"

    def __init__(
        self,
        cfg: JsonConfig,
        *,
        stdout: TextIO | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.when = cfg.when
        self.per_vm = True
        self.dir = Path(cfg.dir)
        self._stdout = stdout
        self._clock = clock

    def __repr__(self) -> str:
        return f"JsonNotifier(dir={str(self.dir)!r})"

    def vm_finished(self, result: VmResult, report: RunReport) -> None:
        if self.when != NotifyWhen.NEVER:
            self._guard(self._write_partial, report)

    def run_finished(self, report: RunReport, *, force: bool = False) -> None:
        """Write the final report; ``force`` (``send_test``) writes only ``{run_id}.json``."""

        def finish() -> None:
            if force or should_send_run(self.when, report):
                self._send_run(report, test=force)
            if not force:
                self._finish(report)

        self._guard(finish)

    # ── internals ──

    def _ensure_dir(self) -> None:
        if not self.dir.is_dir():
            self.dir.mkdir(parents=True, mode=DIR_MODE, exist_ok=True)
            os.chmod(self.dir, DIR_MODE)

    def _write_partial(self, report: RunReport) -> None:
        self._io(
            lambda: (self._ensure_dir(), atomic_write(self._partial(report), dump_report(report))), "write partial"
        )

    def _send_run(self, report: RunReport, *, test: bool = False) -> None:
        text = dump_report(report)

        def write() -> None:
            self._ensure_dir()
            atomic_write(self.dir / f"{report.run_id}.json", text)
            if self.cfg.write_latest and not test:
                atomic_write(self.dir / LATEST, text)

        self._io(write, "write report")
        if self.cfg.stdout:
            out = self._stdout or sys.stdout
            out.write(text)
            out.flush()

    def _finish(self, report: RunReport) -> None:
        """Remove this run's partial and apply retention (runs even when not sending)."""
        self._io(lambda: self._partial(report).unlink(missing_ok=True), "remove partial")
        if self.dir.is_dir():
            self._io(lambda: self._retention(report.run_id), "apply retention")

    def _partial(self, report: RunReport) -> Path:
        return self.dir / f"{report.run_id}{PARTIAL_SUFFIX}"

    def _retention(self, current_run: str) -> None:
        names = sorted(p.name for p in self.dir.iterdir())
        if self.cfg.keep > 0:
            reports = [n for n in names if _REPORT_RE.match(n)]
            for name in reports[: max(0, len(reports) - self.cfg.keep)]:
                (self.dir / name).unlink(missing_ok=True)
                log.info("REPORT_PRUNED file=%s", name)
        now = self._clock()
        for name in names:
            if _PARTIAL_RE.match(name) and name != f"{current_run}{PARTIAL_SUFFIX}":
                path = self.dir / name
                with contextlib.suppress(FileNotFoundError):
                    if now - path.stat().st_mtime > STALE_PARTIAL_S:
                        path.unlink()
                        log.info("REPORT_PRUNED file=%s reason=stale-partial", name)

    def _io(self, fn: Callable[[], object], what: str) -> None:
        try:
            fn()
        except OSError as exc:
            target = exc.filename or self.dir
            raise notify_error(self.name, f"{what} failed: {target}: {exc.strerror or type(exc).__name__}") from None
