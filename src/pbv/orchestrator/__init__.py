"""pbv.orchestrator — preflight, sanitize, per-VM lifecycle, cleanup, sweep, lock and signals.

Public API wired by ``pbv.cli`` (see docs/briefs/orchestrator.md and SPEC §1–§4, §10).
"""

from pbv.orchestrator.lock import RunLock
from pbv.orchestrator.preflight import PreflightFailure, parse_tags, preflight
from pbv.orchestrator.runner import KEEP_TAG, Runner, exit_code, new_run_id
from pbv.orchestrator.sanitize import PRIVILEGED_KEY, PrivilegedSplit, SanitizePlan, sanitize_config, split_privileged
from pbv.orchestrator.signals import StopFlag

__all__ = [
    "KEEP_TAG",
    "PRIVILEGED_KEY",
    "PreflightFailure",
    "PrivilegedSplit",
    "RunLock",
    "Runner",
    "SanitizePlan",
    "StopFlag",
    "exit_code",
    "new_run_id",
    "parse_tags",
    "preflight",
    "sanitize_config",
    "split_privileged",
]
