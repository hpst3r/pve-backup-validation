"""Service discovery: map enabled guest services to checks via signatures.

Linux lists enabled systemd service unit files; Windows lists services with
start mode Auto. Each matched :class:`Signature` yields a service check plus
one port check per port (``http`` for HTTP signatures, ``tcp_listen``
otherwise). :func:`discover` never raises: a listing failure becomes a single
``_discovery_error`` check that the engine reports as WARN.
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from pbv.checks._common import lines, one_line, ps_argv
from pbv.core import CheckSpec, GuestAgent, OsFamily, PbvError

log = logging.getLogger("pbv.checks")

DISCOVERY_ERROR_TYPE = "_discovery_error"
DISCOVERED_WAIT_S = 60
# Legacy cloudflared log check: network errors are expected on the isolated bridge.
CLOUDFLARED_ERROR_REGEX = r"(?i)error|fatal|failed"
CLOUDFLARED_IGNORE_REGEX = r"network is unreachable|no such host|dial tcp|context deadline"


@dataclass(frozen=True)
class Signature:
    """A known service: name alternatives (``*`` wildcards) and what to check.

    ``protocol``: ``"tcp"`` → ``tcp_listen`` per port, ``"http"`` → ``http``
    per port, ``"log_scan"`` → a ``log_scan`` of the unit (Linux only).
    ``ports == ()`` → service check only.
    """

    names: tuple[str, ...]
    ports: tuple[int, ...] = ()
    protocol: str = "tcp"
    path: str = "/"
    error_regex: str = ""
    ignore_regex: str = ""


LINUX_SIGNATURES: tuple[Signature, ...] = (
    Signature(("apache2", "httpd"), (80,), "http"),
    Signature(("nginx",), (80,), "http"),
    Signature(("postgresql", "postgresql@*"), (5432,)),
    Signature(("mariadb", "mysql", "mysqld"), (3306,)),
    Signature(("redis-server", "redis"), (6379,)),
    Signature(("mongod", "mongodb"), (27017,)),
    Signature(("clickhouse-server",), (9000,)),
    Signature(("docker",)),
    Signature(("elasticsearch",), (9200,), "http"),
    Signature(("rabbitmq-server",), (5672,)),
    Signature(("sshd", "ssh"), (22,)),
    Signature(
        ("cloudflared",),
        protocol="log_scan",
        error_regex=CLOUDFLARED_ERROR_REGEX,
        ignore_regex=CLOUDFLARED_IGNORE_REGEX,
    ),
)

WINDOWS_SIGNATURES: tuple[Signature, ...] = (
    Signature(("W3SVC",), (80,), "http"),
    Signature(("MSSQLSERVER",), (1433,)),
    Signature(("NTDS",), (389, 88)),
    Signature(("DNS",), (53,)),
    Signature(("TermService",), (3389,)),
    Signature(("LanmanServer",), (445,)),
)

LINUX_LIST_ARGV = ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"]
WINDOWS_LIST_ARGV = ps_argv(
    "try { Get-CimInstance -ClassName Win32_Service -Filter 'StartMode=''Auto''' -ErrorAction Stop "
    "| Select-Object -ExpandProperty Name } "
    "catch { Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | Select-Object -ExpandProperty Name }"
)


def parse_linux_units(stdout: str) -> list[str]:
    """Unit names (``.service`` stripped) from ``list-unit-files`` output; templates skipped."""
    out: list[str] = []
    for ln in lines(stdout):
        unit = ln.split()[0]
        if not unit.endswith(".service"):
            continue
        name = unit[: -len(".service")]
        if name and not name.endswith("@") and name not in out:
            out.append(name)
    return out


def parse_windows_services(stdout: str) -> list[str]:
    out: list[str] = []
    for ln in lines(stdout):
        if ln.lower() not in (s.lower() for s in out):
            out.append(ln)
    return out


def match_signatures(services: Sequence[str], signatures: Sequence[Signature], *, case_sensitive: bool) -> list:
    """``[(signature, real service name)]``: first alternative that matches wins."""
    found = []
    for sig in signatures:
        for alt in sig.names:
            if case_sensitive:
                hit = next((s for s in services if fnmatch.fnmatchcase(s, alt)), None)
            else:
                hit = next((s for s in services if fnmatch.fnmatchcase(s.lower(), alt.lower())), None)
            if hit is not None:
                found.append((sig, hit))
                break
    return found


def _spec(ctype: str, name: str, params: dict, only_os: OsFamily, wait_s: int = DISCOVERED_WAIT_S) -> CheckSpec:
    return CheckSpec(type=ctype, name=name, params=params, source="discovered", wait_s=wait_s, only_os=only_os)


def specs_for(sig: Signature, service: str, os: OsFamily) -> list[CheckSpec]:
    """Checks for one matched signature (names like ``systemd:<unit>``, ``http:<port>``)."""
    out: list[CheckSpec] = []
    if os is OsFamily.WINDOWS:
        out.append(_spec("windows_service", f"windows_service:{service}", {"service": service}, os))
    else:
        out.append(_spec("systemd", f"systemd:{service}", {"unit": service}, os))
    if sig.protocol == "log_scan":
        if os is OsFamily.LINUX:
            params = {
                "unit": service,
                "since": "5 min ago",
                "error_regex": sig.error_regex or r"(?i)\b(error|fatal|failed)\b",
                "ignore_regex": sig.ignore_regex,
                "max_matches": 0,
            }
            out.append(_spec("log_scan", f"log_scan:{service}", params, os, wait_s=0))
        return out
    for port in sig.ports:
        if port <= 0:
            continue
        if sig.protocol == "http":
            params = {
                "port": port,
                "scheme": "http",
                "path": sig.path,
                "host": "127.0.0.1",
                "expect_status": None,
                "body_regex": "",
            }
            out.append(_spec("http", f"http:{port}", params, os))
        else:
            out.append(_spec("tcp_listen", f"tcp_listen:{port}", {"port": port}, os))
    return out


def discovery_error(message: str) -> CheckSpec:
    return CheckSpec(
        type=DISCOVERY_ERROR_TYPE,
        name="discovery",
        params={"error": one_line(message, 500)},
        critical=False,
        source="discovered",
    )


def discover(guest: GuestAgent, os: OsFamily, *, timeout_s: float = 60) -> list[CheckSpec]:
    """Discovered checks for ``guest``; never raises (errors → one ``_discovery_error`` check)."""
    if os is OsFamily.UNKNOWN:
        return [discovery_error("OS unknown; service discovery skipped")]
    argv = WINDOWS_LIST_ARGV if os is OsFamily.WINDOWS else LINUX_LIST_ARGV
    try:
        res = guest.exec(list(argv), timeout_s=timeout_s)
        if res.timed_out:
            return [discovery_error(f"listing services timed out after {int(timeout_s)}s")]
        if res.exitcode != 0:
            err = res.stderr.strip() or res.stdout.strip() or "no output"
            return [discovery_error(f"listing services failed (exit {res.exitcode}): {err}")]
        if os is OsFamily.WINDOWS:
            services = parse_windows_services(res.stdout)
            matches = match_signatures(services, WINDOWS_SIGNATURES, case_sensitive=False)
        else:
            services = parse_linux_units(res.stdout)
            matches = match_signatures(services, LINUX_SIGNATURES, case_sensitive=True)
    except PbvError as exc:  # GuestAgentError, ApiError, InterruptedRun, ...
        return [discovery_error(f"{exc.code}: {exc}")]
    except Exception as exc:  # boundary: discovery never raises
        log.debug("DISCOVERY_INTERNAL_ERROR", exc_info=True)
        return [discovery_error(f"INTERNAL_ERROR: {type(exc).__name__}: {exc}")]
    out: list[CheckSpec] = []
    seen: set[str] = set()
    for sig, service in matches:
        for spec in specs_for(sig, service, os):
            if spec.name not in seen:
                seen.add(spec.name)
                out.append(spec)
    log.info(
        "DISCOVERY vmid=%s os=%s services=%d matched=%s",
        getattr(guest, "vmid", "?"),
        os.value,
        len(services),
        ",".join(s for _, s in matches) or "-",
    )
    return out
