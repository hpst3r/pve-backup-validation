"""QEMU guest-agent operations bound to one VM, on top of any :class:`pbv.core.PveApi`."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable, Sequence

from pbv.core import ApiError, ExecResult, GuestAgentError, OsFamily, PveApi

log = logging.getLogger("pbv.pve.agent")

_SKIP_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
)


def _agent_error(vmid: int, what: str, err: ApiError) -> GuestAgentError:
    return GuestAgentError(f"guest agent {what} on VM {vmid} failed: {err}")


class PveGuestAgent:
    """Implements :class:`pbv.core.GuestAgent` for one running VM.

    API failures are re-raised as :class:`GuestAgentError` (with PVE's message),
    except in :meth:`os_family` and :meth:`ip_addresses`, which are
    best-effort: they log a warning and return ``UNKNOWN`` / ``[]``.
    """

    def __init__(
        self,
        api: PveApi,
        vmid: int,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        poll_s: float = 1.0,
    ) -> None:
        self.api = api
        self.vmid = vmid
        self._sleep = sleep
        self._clock = clock
        self._poll_s = poll_s

    def __repr__(self) -> str:
        return f"PveGuestAgent(vmid={self.vmid})"

    def ping(self) -> bool:
        try:
            return self.api.agent_ping(self.vmid)
        except ApiError as e:
            raise _agent_error(self.vmid, "ping", e) from None

    def exec(self, argv: Sequence[str], *, timeout_s: float, input_data: bytes | None = None) -> ExecResult:
        """Run ``argv`` and wait for it; a timeout returns ``timed_out=True, exitcode=None``."""
        start = self._clock()
        try:
            pid = self.api.agent_exec(self.vmid, list(argv), input_data)
            while True:
                st = self.api.agent_exec_status(self.vmid, pid)
                elapsed = self._clock() - start
                if st.exited:
                    return ExecResult(
                        exitcode=None if st.signal is not None and st.exitcode is None else st.exitcode,
                        stdout=st.stdout,
                        stderr=st.stderr,
                        duration_s=elapsed,
                        truncated=st.out_truncated or st.err_truncated,
                    )
                remaining = timeout_s - elapsed
                if remaining <= 0:
                    log.warning(
                        "GUEST_EXEC_TIMEOUT vmid=%s pid=%s timeout=%gs argv0=%s", self.vmid, pid, timeout_s, argv[0]
                    )
                    return ExecResult(exitcode=None, stdout="", stderr="", duration_s=elapsed, timed_out=True)
                self._sleep(min(self._poll_s, remaining))
        except ApiError as e:
            raise _agent_error(self.vmid, "exec", e) from None

    def write_file(self, path: str, content: bytes) -> None:
        try:
            self.api.agent_file_write(self.vmid, path, content)
        except ApiError as e:
            raise _agent_error(self.vmid, f"file-write {path}", e) from None

    def os_family(self) -> OsFamily:
        try:
            info = self.api.agent_osinfo(self.vmid)
        except (ApiError, GuestAgentError) as e:
            log.warning("GUEST_OSINFO_FAIL vmid=%s reason=%s", self.vmid, e)
            return OsFamily.UNKNOWN
        os_id = str(info.get("id") or "").strip().lower()
        if os_id == "mswindows":
            return OsFamily.WINDOWS
        return OsFamily.LINUX if os_id else OsFamily.UNKNOWN

    def ip_addresses(self) -> list[str]:
        """Usable guest IPs: no loopback/link-local, IPv4 first, order kept, deduplicated."""
        try:
            ifaces = self.api.agent_network_interfaces(self.vmid)
        except (ApiError, GuestAgentError) as e:
            log.warning("GUEST_IPS_FAIL vmid=%s reason=%s", self.vmid, e)
            return []
        v4: list[str] = []
        v6: list[str] = []
        for iface in ifaces:
            if iface.get("name") == "lo":
                continue
            for entry in iface.get("ip-addresses") or []:
                try:
                    ip = ipaddress.ip_address(str(entry.get("ip-address", "")).split("%", 1)[0])
                except ValueError:
                    continue
                if any(ip.version == net.version and ip in net for net in _SKIP_NETS):
                    continue
                bucket = v4 if ip.version == 4 else v6
                if str(ip) not in bucket:
                    bucket.append(str(ip))
        return v4 + v6
