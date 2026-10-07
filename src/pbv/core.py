"""Frozen shared contract for pbv (Proxmox Backup Validation).

Every subpackage (``pbv.pve``, ``pbv.checks``, ``pbv.notify``,
``pbv.orchestrator``) imports ONLY the standard library, :mod:`pbv.core` and
:mod:`pbv.config`. They never import each other; ``pbv.cli`` wires them.

Changing this module is an architect decision. Workers report disagreements as
``contract_issues`` instead of editing it.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

SCHEMA_VERSION = 1
"""Version of the JSON report format produced by :func:`report_to_dict`."""


# ──────────────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────────────


class PbvError(Exception):
    """Base class for every expected pbv failure.

    ``code`` is a short, stable, SCREAMING_SNAKE identifier that ends up in
    reports and notifications (e.g. ``RESTORE_FAIL``). Messages must never
    contain secrets (tokens, passwords).
    """

    code = "PBV_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class ConfigError(PbvError):
    """Invalid or missing configuration. Exit code 2."""

    code = "CONFIG_ERROR"


class PreflightError(PbvError):
    """The target environment is unsafe or unusable. Exit code 2.

    ``steps`` carries the preflight steps run so far (the last one failed).
    """

    code = "PREFLIGHT_FAIL"

    def __init__(self, message: str, *, steps: list[StepResult] | None = None, code: str | None = None) -> None:
        super().__init__(message, code=code)
        self.steps: list[StepResult] = list(steps or [])


class ApiError(PbvError):
    """A Proxmox VE API call failed.

    ``status`` is the HTTP status (``None`` for connection/TLS errors).
    ``transient`` is True when a retry may succeed (connection reset, timeout,
    HTTP 5xx except 501). Clients retry transient errors themselves before
    raising; callers treat any ApiError that reaches them as final.
    """

    code = "API_ERROR"

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        transient: bool = False,
        code: str | None = None,
    ) -> None:
        super().__init__(message, code=code)
        self.status = status
        self.transient = transient


class TaskFailedError(PbvError):
    """A PVE task (UPID) finished with an exit status other than ``OK``."""

    code = "TASK_FAIL"

    def __init__(self, message: str, *, upid: str, exitstatus: str, code: str | None = None) -> None:
        super().__init__(message, code=code)
        self.upid = upid
        self.exitstatus = exitstatus


class PbvTimeoutError(PbvError):
    """Something did not finish within its configured deadline."""

    code = "TIMEOUT"


class GuestAgentError(PbvError):
    """The QEMU guest agent is missing, not responding, or refused a command."""

    code = "GUEST_AGENT_ERROR"


class CleanupError(PbvError):
    """A temporary VM could not be destroyed. Always critical. Exit code 3."""

    code = "CLEANUP_FAIL"


class SafetyError(PbvError):
    """A guard refused a destructive action (e.g. destroying a non-temp VM)."""

    code = "SAFETY_REFUSED"


class InterruptedRun(PbvError):
    """SIGINT/SIGTERM received; cleanup still runs. Exit code 130."""

    code = "INTERRUPTED"


# ──────────────────────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────────────────────


class Status(enum.StrEnum):
    """Outcome of a check, step, VM or run. Ordered by severity via ``rank``."""

    PASS = "pass"  # noqa: S105
    WARN = "warn"  # non-critical check failed, or something degraded
    FAIL = "fail"
    ERROR = "error"  # pbv itself could not complete (API down, bug)
    SKIPPED = "skipped"

    @property
    def rank(self) -> int:
        return {"skipped": 0, "pass": 1, "warn": 2, "fail": 3, "error": 4}[self.value]

    @staticmethod
    def worst(statuses: Sequence[Status], default: Status = None) -> Status:  # type: ignore[assignment]
        if not statuses:
            return default if default is not None else Status.SKIPPED
        return max(statuses, key=lambda s: s.rank)


class OsFamily(enum.StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class NotifyWhen(enum.StrEnum):
    ALWAYS = "always"
    FAILURE = "failure"  # VM/run status worse than PASS (warn, fail, error)
    NEVER = "never"


# ──────────────────────────────────────────────────────────────────────────────
# Data passed between components
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BackupRef:
    """One backup snapshot visible on the target node's PBS storage."""

    volid: str  # e.g. "pbs:backup/vm/105/2026-10-01T02:00:00Z"
    vmid: int
    ctime: int  # unix seconds
    size: int  # bytes (0 if unknown)
    format: str = ""  # e.g. "pbs-vm"
    notes: str = ""  # backup notes (often the guest name)
    verified: bool | None = None  # PBS verify state if reported, else None
    encrypted: bool | None = None


@dataclass(frozen=True)
class TaskResult:
    upid: str
    exitstatus: str  # "OK" on success; "WARNINGS: n" also counts as ok
    ok: bool
    log_tail: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecStatus:
    """Raw ``agent/exec-status`` response (output already base64-decoded)."""

    exited: bool
    exitcode: int | None = None
    stdout: str = ""
    stderr: str = ""
    out_truncated: bool = False
    err_truncated: bool = False
    signal: int | None = None


@dataclass(frozen=True)
class ExecResult:
    """A finished (or timed-out) guest/host command."""

    exitcode: int | None  # None if killed/timed out
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    truncated: bool = False


@dataclass(frozen=True)
class VmTarget:
    """One VM to validate, resolved from config."""

    vmid: int  # original (source) VMID as found in backups
    temp_vmid: int
    mode: str  # "auto" | "hybrid" | "manual"
    os: OsFamily | None  # None = detect via guest agent
    checks: tuple[CheckSpec, ...]  # explicit checks from config
    boot_timeout_s: int
    name_hint: str = ""  # from config `name`, else filled from backup/config


@dataclass(frozen=True)
class CheckSpec:
    """A single check to run against a booted temporary VM.

    ``type`` is one of the names in SPEC.md §Checks. ``params`` holds the
    type-specific fields exactly as validated by :mod:`pbv.config`.
    """

    type: str
    name: str  # human label; config default "<type>:<main param>"
    params: Mapping[str, Any] = field(default_factory=dict)
    critical: bool = True  # False -> failure counts as WARN not FAIL
    timeout_s: int = 60  # max time for one attempt
    wait_s: int = 0  # keep retrying a failing check until this many seconds elapsed
    source: str = "config"  # "config" | "discovered" | "global"
    only_os: OsFamily | None = None  # run only on this OS; otherwise SKIPPED


@dataclass(frozen=True)
class CheckContext:
    """Facts about the running temporary VM, handed to every check."""

    run_id: str
    target_node: str
    vmid: int  # original
    temp_vmid: int
    vm_name: str
    os: OsFamily
    guest_ips: tuple[str, ...]
    work_dir: Path  # per-VM artifact dir (logs, screenshots, script output)
    config_dir: Path  # directory of the config file; relative script paths resolve here


@dataclass
class CheckResult:
    name: str
    type: str
    status: Status
    summary: str  # one line, safe for notifications
    detail: str = ""  # longer diagnostic text (truncated by producer to <= 8 KiB)
    duration_s: float = 0.0
    attempts: int = 1
    critical: bool = True
    source: str = "config"


@dataclass
class StepResult:
    """One lifecycle step (restore, sanitize, boot, cleanup, ...)."""

    name: str
    status: Status
    started_at: str  # ISO-8601 UTC
    duration_s: float
    message: str = ""
    error_code: str = ""  # PbvError.code when status is FAIL/ERROR


@dataclass
class VmResult:
    vmid: int
    temp_vmid: int
    name: str
    status: Status
    started_at: str
    duration_s: float
    backup: BackupRef | None = None
    failure_code: str = ""  # first fatal error code, e.g. "RESTORE_FAIL"
    failure_message: str = ""
    steps: list[StepResult] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    guest_ips: list[str] = field(default_factory=list)
    os: str = OsFamily.UNKNOWN.value
    screenshots: list[str] = field(default_factory=list)  # absolute paths
    log_file: str = ""
    sanitized: list[str] = field(default_factory=list)  # human list of config changes applied
    cleanup_ok: bool = True  # False -> temp VM may still exist (critical)


@dataclass
class RunReport:
    run_id: str  # e.g. "20261007T020000Z-ab12"
    target_node: str
    started_at: str
    finished_at: str
    duration_s: float
    status: Status
    vms: list[VmResult] = field(default_factory=list)
    preflight: list[StepResult] = field(default_factory=list)
    leftovers_swept: list[int] = field(default_factory=list)
    sweep_failures: list[str] = field(default_factory=list)  # "<temp vmid>: <code> <message>" — still present
    interrupted: bool = False
    notify_errors: list[str] = field(default_factory=list)  # "<notifier>: <code> <message>"
    tool_version: str = ""
    schema_version: int = SCHEMA_VERSION

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for vm in self.vms:
            out[vm.status.value] += 1
        return out


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plain(obj: Any) -> Any:
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj


def report_to_dict(report: RunReport) -> dict[str, Any]:
    """Stable JSON-ready representation of a run (see SPEC.md §JSON report)."""
    d = _plain(asdict(report))
    d["counts"] = report.counts
    return d


# ──────────────────────────────────────────────────────────────────────────────
# Interfaces
# ──────────────────────────────────────────────────────────────────────────────


@runtime_checkable
class PveApi(Protocol):
    """Typed Proxmox VE REST operations against ONE target node.

    Implemented by ``pbv.pve.PveClient`` (HTTPS + API token) and by the
    in-memory ``pbv.testing.fakes.FakePve``. All methods raise
    :class:`ApiError` on failure (after the implementation's own retries).
    VM config values are the raw PVE strings (e.g. ``"virtio=AA:..,bridge=vmbr0"``).
    """

    node: str

    def version(self) -> dict[str, Any]: ...
    def cluster_status(self) -> list[dict[str, Any]]: ...
    def node_networks(self) -> list[dict[str, Any]]: ...
    def storage_list(self) -> list[dict[str, Any]]: ...
    def list_backups(self, storage: str) -> list[BackupRef]: ...
    def list_vms(self) -> list[dict[str, Any]]: ...  # each: vmid(int), name, status, tags(str)
    def vm_exists(self, vmid: int) -> bool: ...
    def restore_vm(
        self,
        vmid: int,
        archive: str,
        storage: str,
        *,
        unique: bool = True,
        pool: str | None = None,
        bwlimit_kib: int | None = None,
    ) -> str: ...  # returns UPID
    def wait_task(self, upid: str, timeout_s: float) -> TaskResult: ...  # raises PbvTimeoutError
    def get_vm_config(self, vmid: int) -> dict[str, str]: ...
    def update_vm_config(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str] = ()) -> None: ...
    def vm_status(self, vmid: int) -> str: ...  # "running" | "stopped" | ...
    def start_vm(self, vmid: int) -> str: ...  # UPID
    def stop_vm(self, vmid: int, *, skiplock: bool = False) -> str: ...  # UPID (hard stop)
    def destroy_vm(self, vmid: int, *, skiplock: bool = False) -> str: ...  # UPID; purge + destroy-unreferenced-disks
    def stop_task(self, upid: str) -> None: ...  # DELETE /nodes/{node}/tasks/{upid}
    def agent_ping(self, vmid: int) -> bool: ...  # False when agent not (yet) answering
    def agent_exec(self, vmid: int, argv: Sequence[str], input_data: bytes | None = None) -> int: ...  # pid
    def agent_exec_status(self, vmid: int, pid: int) -> ExecStatus: ...
    def agent_file_write(self, vmid: int, path: str, content: bytes) -> None: ...
    def agent_network_interfaces(self, vmid: int) -> list[dict[str, Any]]: ...
    def agent_osinfo(self, vmid: int) -> dict[str, Any]: ...
    def monitor(self, vmid: int, command: str) -> str: ...  # HMP command, returns text


@runtime_checkable
class GuestAgent(Protocol):
    """Guest-agent operations bound to one running VM (``pbv.pve.PveGuestAgent``)."""

    vmid: int

    def ping(self) -> bool: ...
    def exec(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        input_data: bytes | None = None,
    ) -> ExecResult: ...  # never raises on non-zero exit; raises GuestAgentError if agent fails
    def write_file(self, path: str, content: bytes) -> None: ...
    def os_family(self) -> OsFamily: ...  # via get-osinfo; UNKNOWN if undeterminable
    def ip_addresses(self) -> list[str]: ...  # non-loopback IPv4 then IPv6


@runtime_checkable
class NodeShell(Protocol):
    """Root shell on the restore node, for operations PVE 9 restricts to ``root@pam``.

    API tokens are never ``root@pam``, so these go through ``qm`` as root, either
    locally (pbv runs on the restore node) or over SSH (``pbv.pve.NodeShellRunner``).
    Needed for: removing non-mapped ``hostpci``/``usb`` devices, real-device
    ``serial``/``parallel`` ports, ``args``/``hookscript``; and HMP
    ``screendump`` (root-only in PVE 9).
    """

    def probe(self) -> str: ...  # e.g. "ssh root@node: ok"; raises PbvError(code="NODE_SHELL_FAIL")
    def unlock(self, vmid: int) -> None: ...  # `qm unlock <vmid>`; raises PbvError(code="NODE_SHELL_FAIL")
    def sysctl(
        self, key: str
    def sysctl(self, key: str) -> str: ...  # `sysctl -n <key>` (key ^[a-z0-9_][a-z0-9_.-]*$); raises PbvError(code="NODE_SHELL_FAIL")
    def qm_set(
        self, vmid: int, set_: Mapping[str, str], delete: Sequence[str]
    ) -> None: ...  # raises PbvError(code="NODE_SHELL_FAIL")
    def screendump(
        self, vmid: int, dest: Path
    ) -> Path | None: ...  # dest without suffix; returns local PNG path; never raises


@runtime_checkable
class ConsoleCapturer(Protocol):
    """Takes a screenshot of a VM's VGA console (``pbv.pve.ConsoleCapture``)."""

    def capture(self, vmid: int, dest: Path) -> Path | None: ...  # dest without suffix; None on failure, never raises


@runtime_checkable
class CheckSuite(Protocol):
    """Plans and runs checks (``pbv.checks.CheckEngine``)."""

    def plan(self, target: VmTarget, guest: GuestAgent, os: OsFamily) -> list[CheckSpec]: ...
    def run(self, spec: CheckSpec, guest: GuestAgent, ctx: CheckContext) -> CheckResult:
        """Never raises (InterruptedRun from a guest wrapper becomes an ERROR result);
        callers check their stop flag after each call."""
        ...


@runtime_checkable
class Notifier(Protocol):
    """A notification sink (email, ntfy, JSON file, Telegram)."""

    name: str

    def vm_finished(self, result: VmResult, report: RunReport) -> None: ...
    def run_finished(self, report: RunReport) -> None: ...
