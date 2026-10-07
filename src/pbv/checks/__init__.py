"""pbv.checks — check engine, check types and service discovery (SPEC §5).

The architect wires :class:`CheckEngine` (a :class:`pbv.core.CheckSuite`).
"""

from pbv.checks.discovery import (
    DISCOVERY_ERROR_TYPE,
    LINUX_SIGNATURES,
    WINDOWS_SIGNATURES,
    Signature,
    discover,
)
from pbv.checks.engine import CheckEngine
from pbv.checks.scripts import default_run_host

__all__ = [
    "DISCOVERY_ERROR_TYPE",
    "LINUX_SIGNATURES",
    "WINDOWS_SIGNATURES",
    "CheckEngine",
    "Signature",
    "default_run_host",
    "discover",
]
