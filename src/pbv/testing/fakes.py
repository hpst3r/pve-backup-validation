"""In-memory fakes of the core interfaces (frozen contract, architect-owned).

Used by every package's tests and by the end-to-end tests. The fakes are
deliberately strict: they raise :class:`ApiError` for operations PVE would
reject (unknown VMID, starting a running VM, destroying a running VM).

Scripting guest behaviour::

    pve = FakePve(node="restore01")
    pve.add_backup(BackupRef(volid="pbs:backup/vm/105/2026-10-01T02:00:00Z", vmid=105, ctime=..., size=...),
                   config={"name": "web01", "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0", ...})
    pve.guest_profile[105] = GuestProfile(os=OsFamily.LINUX, boot_polls=2)
    pve.guest_profile[105].on_exec = lambda argv, input_data: (0, "active\n", "")

Guest profiles are keyed by SOURCE vmid; restored temp VMs inherit them.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from pbv.core import (
    ApiError,
    BackupRef,
    CheckContext,
    CheckResult,
    CheckSpec,
    ExecResult,
    ExecStatus,
    GuestAgentError,
    OsFamily,
    PbvTimeoutError,
    RunReport,
    Status,
    TaskResult,
    VmResult,
    VmTarget,
)

import re

# Config keys whose modification PVE 9 restricts to root@pam (non-mapped devices, host args).
PRIVILEGED_KEY = re.compile(r"^(?:(?:hostpci|usb|serial|parallel|virtiofs)\d+|args|hookscript)$")

ExecHandler = Callable[[Sequence[str], "bytes | None"], tuple[int, str, str]]


@dataclass
class GuestProfile:
    """Scripted behaviour of a restored guest."""

    os: OsFamily = OsFamily.LINUX
    boot_polls: int = 1  # agent_ping returns False this many times after start
    never_boots: bool = False
    ips: list[str] = field(default_factory=lambda: ["10.99.0.5"])
    on_exec: ExecHandler | None = None  # default: exit 0, empty output
    exec_polls: int = 0  # exec-status reports not-exited this many times
    files: dict[str, bytes] = field(default_factory=dict)  # written via agent_file_write


@dataclass
class FakeVm:
    vmid: int
    config: dict[str, str]
    status: str = "stopped"
    source_vmid: int | None = None
    pings_left: int = 0
    exec_calls: list[tuple[list[str], bytes | None]] = field(default_factory=list)


@dataclass
class FakeStorage:
    storage: str
    type: str
    content: str
    avail: int = 10**12
    total: int = 2 * 10**12
    active: int = 1
    enabled: int = 1


class FakePve:
    """In-memory :class:`pbv.core.PveApi` for ONE node."""

    def __init__(self, node: str = "restore01", *, cluster: list[dict[str, Any]] | None = None) -> None:
        self.node = node
        self._lock = threading.RLock()
        self.vms: dict[int, FakeVm] = {}
        self.backups: dict[str, tuple[BackupRef, dict[str, str]]] = {}
        self.guest_profile: dict[int, GuestProfile] = {}
        self.cluster = (
            cluster if cluster is not None else [{"type": "node", "name": node, "online": 1, "local": 1, "nodeid": 0}]
        )
        self.networks: list[dict[str, Any]] = [
            {
                "iface": "vmbr0",
                "type": "bridge",
                "bridge_ports": "eno1",
                "cidr": "192.0.2.10/24",
                "gateway": "192.0.2.1",
                "active": 1,
            },
            {"iface": "vmbr99", "type": "bridge", "bridge_ports": "", "active": 1},
        ]
        self.storages: dict[str, FakeStorage] = {
            "pbs": FakeStorage("pbs", "pbs", "backup"),
            "local-lvm": FakeStorage("local-lvm", "lvmthin", "images,rootdir"),
        }
        self.pve_version = {"version": "9.0.10", "release": "9.0", "repoid": "deadbeef"}
        self.tasks: dict[str, TaskResult] = {}
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.monitor_log: list[tuple[int, str]] = []
        self.stopped_tasks: list[str] = []
        self.hung_tasks: set[str] = set()  # UPIDs whose wait_task raises PbvTimeoutError
        self.restore_hangs: set[int] = set()  # source vmids whose restore task never finishes
        self.fail_next: dict[str, ApiError] = {}  # method name -> error raised once
        self.token_is_root = False  # PVE 9: tokens are never root@pam; privileged keys and screendump refused
        self.restore_fails: dict[int, str] = {}  # source vmid -> task exitstatus
        self.destroy_fails: set[int] = set()  # temp vmids whose destroy task fails
        self._upid = itertools.count(1)
        self._pid = itertools.count(1000)
        self._execs: dict[tuple[int, int], tuple[int, str, str, int]] = {}

    # ── helpers for tests ──────────────────────────────────────────────────────
    def add_backup(self, ref: BackupRef, config: Mapping[str, str] | None = None) -> None:
        cfg = dict(
            config or {"name": f"vm{ref.vmid}", "memory": "2048", "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0"}
        )
        self.backups[ref.volid] = (ref, cfg)

    def add_vm(self, vmid: int, config: Mapping[str, str] | None = None, status: str = "stopped") -> FakeVm:
        vm = FakeVm(vmid=vmid, config=dict(config or {"name": f"vm{vmid}"}), status=status)
        self.vms[vmid] = vm
        return vm

    def _record(self, name: str, *args: Any) -> None:
        self.calls.append((name, args))
        err = self.fail_next.pop(name, None)
        if err is not None:
            raise err

    def _vm(self, vmid: int) -> FakeVm:
        vm = self.vms.get(vmid)
        if vm is None:
            raise ApiError(f"Configuration file 'nodes/{self.node}/qemu-server/{vmid}.conf' does not exist", status=500)
        return vm

    def _task(self, kind: str, ok: bool = True, exitstatus: str = "OK") -> str:
        upid = f"UPID:{self.node}:{next(self._upid):08X}:0:0:{kind}::pbv@pve!t:"
        self.tasks[upid] = TaskResult(
            upid=upid,
            exitstatus=exitstatus if not ok else "OK",
            ok=ok,
            log_tail=(f"{kind} {'ok' if ok else exitstatus}",),
        )
        return upid

    def _profile(self, vm: FakeVm) -> GuestProfile:
        return self.guest_profile.get(vm.source_vmid if vm.source_vmid is not None else vm.vmid, GuestProfile())

    # ── PveApi ─────────────────────────────────────────────────────────────────
    def version(self) -> dict[str, Any]:
        self._record("version")
        return dict(self.pve_version)

    def cluster_status(self) -> list[dict[str, Any]]:
        self._record("cluster_status")
        return [dict(x) for x in self.cluster]

    def node_networks(self) -> list[dict[str, Any]]:
        self._record("node_networks")
        return [dict(x) for x in self.networks]

    def storage_list(self) -> list[dict[str, Any]]:
        self._record("storage_list")
        return [dict(s.__dict__) for s in self.storages.values()]

    def list_backups(self, storage: str) -> list[BackupRef]:
        self._record("list_backups", storage)
        if storage not in self.storages:
            raise ApiError(f"storage '{storage}' does not exist", status=500)
        return [ref for ref, _ in self.backups.values() if ref.volid.startswith(f"{storage}:")]

    def list_vms(self) -> list[dict[str, Any]]:
        self._record("list_vms")
        return [
            {"vmid": v.vmid, "name": v.config.get("name", ""), "status": v.status, "tags": v.config.get("tags", "")}
            for v in self.vms.values()
        ]

    def vm_exists(self, vmid: int) -> bool:
        self._record("vm_exists", vmid)
        return vmid in self.vms

    def restore_vm(
        self,
        vmid: int,
        archive: str,
        storage: str,
        *,
        unique: bool = True,
        pool: str | None = None,
        bwlimit_kib: int | None = None,
    ) -> str:
        self._record("restore_vm", vmid, archive, storage, unique, pool, bwlimit_kib)
        with self._lock:
            if vmid in self.vms:
                raise ApiError(
                    f"unable to restore VM {vmid} - VM {vmid} already exists on node '{self.node}'", status=500
                )
            if archive not in self.backups:
                raise ApiError(f"volume '{archive}' does not exist", status=500)
            if storage not in self.storages:
                raise ApiError(f"storage '{storage}' does not exist", status=500)
            ref, cfg = self.backups[archive]
            fail = self.restore_fails.get(ref.vmid)
            if fail:
                # PVE leaves a partially-created, locked VM behind on failure.
                self.vms[vmid] = FakeVm(vmid=vmid, config={"lock": "create"}, source_vmid=ref.vmid)
                return self._task("qmrestore", ok=False, exitstatus=fail)
            if ref.vmid in self.restore_hangs:
                self.vms[vmid] = FakeVm(vmid=vmid, config={"lock": "create"}, source_vmid=ref.vmid)
                upid = self._task("qmrestore")
                self.hung_tasks.add(upid)
                return upid
            new = dict(cfg)
            if unique:
                for k, v in list(new.items()):
                    if k.startswith("net") and "=" in v:
                        model, _, rest = v.partition("=")
                        _mac, _, tail = rest.partition(",")
                        new[k] = f"{model}=BC:24:11:FF:{vmid % 256:02X}:{int(k[3:] or 0):02X}" + (
                            f",{tail}" if tail else ""
                        )
            self.vms[vmid] = FakeVm(vmid=vmid, config=new, source_vmid=ref.vmid)
            return self._task("qmrestore")

    def wait_task(self, upid: str, timeout_s: float) -> TaskResult:
        self._record("wait_task", upid, timeout_s)
        if upid not in self.tasks:
            raise ApiError(f"no such task {upid}", status=500)
        if timeout_s <= 0 or upid in self.hung_tasks:
            raise PbvTimeoutError(f"task {upid} did not finish")
        return self.tasks[upid]

    def stop_task(self, upid: str) -> None:
        self._record("stop_task", upid)
        if upid not in self.tasks:
            raise ApiError(f"no such task {upid}", status=500)
        self.stopped_tasks.append(upid)

    def get_vm_config(self, vmid: int) -> dict[str, str]:
        self._record("get_vm_config", vmid)
        return dict(self._vm(vmid).config)

    def update_vm_config(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str] = ()) -> None:
        self._record("update_vm_config", vmid, dict(set_), tuple(delete))
        vm = self._vm(vmid)
        overlap = set(set_) & set(delete)
        if overlap:
            raise ApiError(f"cannot set and delete the same option(s): {sorted(overlap)}", status=400)
        if self.token_is_root is False:
            for k in [*set_, *delete]:
                if PRIVILEGED_KEY.match(k) and not (
                    k.startswith("serial") and set_.get(k, vm.config.get(k)) == "socket"
                ):
                    raise ApiError(f"only root can modify '{k}' config for real devices", status=500)
        vm.config.update(set_)
        for k in delete:
            vm.config.pop(k, None)

    def vm_status(self, vmid: int) -> str:
        self._record("vm_status", vmid)
        return self._vm(vmid).status

    def start_vm(self, vmid: int) -> str:
        self._record("start_vm", vmid)
        vm = self._vm(vmid)
        if vm.status == "running":
            raise ApiError(f"VM {vmid} already running", status=500)
        for k, v in vm.config.items():
            if k.startswith(("hostpci", "usb")):
                return self._task("qmstart", ok=False, exitstatus=f"cannot start: {k} device not present on this node")
            if k.startswith("net") and "bridge=" in v:
                bridge = v.split("bridge=", 1)[1].split(",", 1)[0]
                if bridge not in {n["iface"] for n in self.networks}:
                    return self._task("qmstart", ok=False, exitstatus=f"bridge '{bridge}' does not exist")
            if "media=cdrom" in v and not v.startswith("none") and not v.startswith("cdrom"):
                vol = v.split(",", 1)[0]
                if vol.split(":", 1)[0] not in self.storages:
                    return self._task(
                        "qmstart", ok=False, exitstatus=f"storage '{vol.split(':', 1)[0]}' does not exist"
                    )
        vm.status = "running"
        prof = self._profile(vm)
        vm.pings_left = prof.boot_polls
        return self._task("qmstart")

    def stop_vm(self, vmid: int, *, skiplock: bool = False) -> str:
        self._record("stop_vm", vmid, skiplock)
        if skiplock and self.token_is_root is False:
            raise ApiError("skiplock: Only root may use this option.", status=400)
        vm = self._vm(vmid)
        if vm.config.get("lock") and not skiplock:
            raise ApiError(f"VM is locked ({vm.config['lock']})", status=500)
        vm.status = "stopped"
        return self._task("qmstop")

    def destroy_vm(self, vmid: int, *, skiplock: bool = False) -> str:
        self._record("destroy_vm", vmid, skiplock)
        if skiplock and self.token_is_root is False:
            raise ApiError("skiplock: Only root may use this option.", status=400)
        vm = self._vm(vmid)
        if vm.config.get("lock") and not skiplock:
            raise ApiError(f"VM is locked ({vm.config['lock']})", status=500)
        if vm.config.get("protection") == "1":
            raise ApiError("can't remove VM - protection mode enabled", status=500)
        if vm.status == "running":
            raise ApiError(f"VM {vmid} is running - destroy failed", status=500)
        if vmid in self.destroy_fails:
            return self._task("qmdestroy", ok=False, exitstatus="lvremove failed")
        del self.vms[vmid]
        return self._task("qmdestroy")

    def _running(self, vmid: int) -> FakeVm:
        vm = self._vm(vmid)
        if vm.status != "running":
            raise ApiError(f"VM {vmid} is not running", status=500)
        return vm

    def agent_ping(self, vmid: int) -> bool:
        self._record("agent_ping", vmid)
        vm = self._running(vmid)
        prof = self._profile(vm)
        if prof.never_boots:
            return False
        if vm.pings_left > 0:
            vm.pings_left -= 1
            return False
        return True

    def _agent_ready(self, vmid: int) -> FakeVm:
        vm = self._running(vmid)
        if self._profile(vm).never_boots or vm.pings_left > 0:
            raise ApiError("QEMU guest agent is not running", status=500)
        return vm

    def agent_exec(self, vmid: int, argv: Sequence[str], input_data: bytes | None = None) -> int:
        self._record("agent_exec", vmid, list(argv), input_data)
        vm = self._agent_ready(vmid)
        prof = self._profile(vm)
        vm.exec_calls.append((list(argv), input_data))
        handler = prof.on_exec or (lambda a, i: (0, "", ""))
        code, out, err = handler(list(argv), input_data)
        pid = next(self._pid)
        self._execs[(vmid, pid)] = (code, out, err, prof.exec_polls)
        return pid

    def agent_exec_status(self, vmid: int, pid: int) -> ExecStatus:
        self._record("agent_exec_status", vmid, pid)
        self._agent_ready(vmid)
        if (vmid, pid) not in self._execs:
            raise ApiError("Agent error: Invalid parameter 'pid'", status=500)
        code, out, err, polls = self._execs[(vmid, pid)]
        if polls > 0:
            self._execs[(vmid, pid)] = (code, out, err, polls - 1)
            return ExecStatus(exited=False)
        return ExecStatus(exited=True, exitcode=code, stdout=out, stderr=err)

    def agent_file_write(self, vmid: int, path: str, content: bytes) -> None:
        self._record("agent_file_write", vmid, path, len(content))
        vm = self._agent_ready(vmid)
        self._profile(vm).files[path] = bytes(content)

    def agent_network_interfaces(self, vmid: int) -> list[dict[str, Any]]:
        self._record("agent_network_interfaces", vmid)
        vm = self._agent_ready(vmid)
        prof = self._profile(vm)
        out: list[dict[str, Any]] = [
            {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8}]}
        ]
        out.append(
            {
                "name": "eth0",
                "hardware-address": "bc:24:11:ff:00:00",
                "ip-addresses": [
                    {"ip-address-type": "ipv6" if ":" in ip else "ipv4", "ip-address": ip, "prefix": 24}
                    for ip in prof.ips
                ],
            }
        )
        return out

    def agent_osinfo(self, vmid: int) -> dict[str, Any]:
        self._record("agent_osinfo", vmid)
        vm = self._agent_ready(vmid)
        prof = self._profile(vm)
        if prof.os == OsFamily.WINDOWS:
            return {
                "id": "mswindows",
                "name": "Microsoft Windows",
                "kernel-release": "20348",
                "version": "Microsoft Windows Server 2022",
            }
        if prof.os == OsFamily.LINUX:
            return {"id": "debian", "name": "Debian GNU/Linux", "kernel-release": "6.1.0-25-amd64", "version-id": "12"}
        return {}

    def monitor(self, vmid: int, command: str) -> str:
        self._record("monitor", vmid, command)
        self._running(vmid)
        if self.token_is_root is False and command.strip().startswith("screendump"):
            raise ApiError("root-only command 'screendump'", status=500)
        self.monitor_log.append((vmid, command))
        return ""


class FakeGuest:
    """Scriptable :class:`pbv.core.GuestAgent` for check tests.

    ``responses`` maps a predicate over argv to (exitcode, stdout, stderr);
    the first predicate that matches wins. Unmatched commands return
    ``default``. Every call is recorded in ``calls``.
    """

    def __init__(self, vmid: int = 900105, os: OsFamily = OsFamily.LINUX, ips: Sequence[str] = ("10.99.0.5",)) -> None:
        self.vmid = vmid
        self._os = os
        self._ips = list(ips)
        self.responses: list[
            tuple[Callable[[Sequence[str]], bool], ExecResult | Callable[[Sequence[str], bytes | None], ExecResult]]
        ] = []
        self.default = ExecResult(exitcode=0, stdout="", stderr="", duration_s=0.01)
        self.calls: list[tuple[list[str], float, bytes | None]] = []
        self.files: dict[str, bytes] = {}
        self.alive = True

    def when(
        self,
        predicate: Callable[[Sequence[str]], bool],
        result: ExecResult | Callable[[Sequence[str], bytes | None], ExecResult],
    ) -> None:
        self.responses.append((predicate, result))

    def when_contains(self, needle: str, exitcode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.when(lambda argv: any(needle in a for a in argv), ExecResult(exitcode, stdout, stderr, 0.01))

    def ping(self) -> bool:
        return self.alive

    def exec(self, argv: Sequence[str], *, timeout_s: float, input_data: bytes | None = None) -> ExecResult:
        self.calls.append((list(argv), timeout_s, input_data))
        if not self.alive:
            raise GuestAgentError("QEMU guest agent is not running")
        for pred, res in self.responses:
            if pred(argv):
                return res(argv, input_data) if callable(res) else res
        return self.default

    def write_file(self, path: str, content: bytes) -> None:
        if not self.alive:
            raise GuestAgentError("QEMU guest agent is not running")
        self.files[path] = bytes(content)

    def os_family(self) -> OsFamily:
        return self._os

    def ip_addresses(self) -> list[str]:
        return list(self._ips)


class FakeNodeShell:
    """:class:`pbv.core.NodeShell` that applies ``qm set`` to a :class:`FakePve`."""

    def __init__(self, pve: FakePve | None = None, *, fail: bool = False, probe_fails: bool | None = None) -> None:
        self.pve = pve
        self.fail = fail  # qm_set and screendump (and probe, unless probe_fails is set) fail
        self.probe_fails = probe_fails
        self.qm_calls: list[tuple[int, dict[str, str], list[str]]] = []
        self.screendumps: list[int] = []
        self.unlocks: list[int] = []
        self.sysctls: dict[str, str] = {
            "net.ipv6.conf.vmbr99.disable_ipv6": "1",
            "kernel.hostname": pve.node if pve is not None else "restore01",
        }

    def probe(self) -> str:
        from pbv.core import PbvError

        if self.fail if self.probe_fails is None else self.probe_fails:
            raise PbvError("node shell: ssh exited 255", code="NODE_SHELL_FAIL")
        return "fake node shell ok"

    def qm_set(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str]) -> None:
        from pbv.core import PbvError

        self.qm_calls.append((vmid, dict(set_), list(delete)))
        if self.fail:
            raise PbvError("node shell: ssh exited 255", code="NODE_SHELL_FAIL")
        if self.pve is not None:
            vm = self.pve._vm(vmid)
            vm.config.update(set_)
            for k in delete:
                vm.config.pop(k, None)

    def sysctl(self, key: str) -> str:
        from pbv.core import PbvError

        if self.fail:
            raise PbvError("node shell: ssh exited 255", code="NODE_SHELL_FAIL")
        if key not in self.sysctls:
            raise PbvError(f"node shell: sysctl: cannot stat /proc/sys/{key.replace('.', '/')}", code="NODE_SHELL_FAIL")
        return self.sysctls[key]

    def unlock(self, vmid: int) -> None:
        from pbv.core import PbvError

        self.unlocks.append(vmid)
        if self.fail:
            raise PbvError("node shell: ssh exited 255", code="NODE_SHELL_FAIL")
        if self.pve is not None:
            self.pve._vm(vmid).config.pop("lock", None)

    def screendump(self, vmid: int, dest: Path) -> Path | None:
        self.screendumps.append(vmid)
        if self.fail:
            return None
        p = dest.with_suffix(".png")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x89PNG\r\n\x1a\n")
        return p


class FakeConsole:
    """:class:`pbv.core.ConsoleCapturer` that writes a tiny PNG signature."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.captured: list[int] = []

    def capture(self, vmid: int, dest: Path) -> Path | None:
        self.captured.append(vmid)
        if self.fail:
            return None
        p = dest.with_suffix(".png")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x89PNG\r\n\x1a\n")
        return p


class FakeCheckSuite:
    """:class:`pbv.core.CheckSuite` returning canned results by check name."""

    def __init__(self, planned: Sequence[CheckSpec] = (), results: Mapping[str, Status] | None = None) -> None:
        self.planned = list(planned)
        self.results = dict(results or {})
        self.ran: list[tuple[str, int]] = []

    def plan(self, target: VmTarget, guest: Any, os: OsFamily) -> list[CheckSpec]:
        return list(target.checks) + list(self.planned)

    def run(self, spec: CheckSpec, guest: Any, ctx: CheckContext) -> CheckResult:
        self.ran.append((spec.name, ctx.temp_vmid))
        st = self.results.get(spec.name, Status.PASS)
        if st in (Status.FAIL,) and not spec.critical:
            st = Status.WARN
        return CheckResult(
            name=spec.name,
            type=spec.type,
            status=st,
            summary=f"{spec.name} {st.value}",
            critical=spec.critical,
            source=spec.source,
        )


class RecordingNotifier:
    """:class:`pbv.core.Notifier` that records calls (optionally raising)."""

    def __init__(self, name: str = "recording", raise_exc: Exception | None = None) -> None:
        self.name = name
        self.raise_exc = raise_exc
        self.vm_results: list[VmResult] = []
        self.reports: list[RunReport] = []

    def vm_finished(self, result: VmResult, report: RunReport) -> None:
        self.vm_results.append(result)
        if self.raise_exc:
            raise self.raise_exc

    def run_finished(self, report: RunReport) -> None:
        self.reports.append(report)
        if self.raise_exc:
            raise self.raise_exc
