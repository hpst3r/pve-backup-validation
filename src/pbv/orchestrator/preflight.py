"""Preflight safety guards (SPEC §1).

:func:`preflight` runs every guard in order and returns one ``StepResult``
per guard. The first failing guard raises :class:`PreflightFailure` (a
:class:`pbv.core.PreflightError`) that carries the steps recorded so far, so
the caller can put them in the report. Nothing on the node is modified.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import Any

from pbv.config import Config
from pbv.core import ApiError, PreflightError, PveApi, Status, StepResult, utc_now_iso

log = logging.getLogger("pbv.orchestrator")

_IP_FIELDS = ("cidr", "address", "cidr6", "address6", "gateway", "gateway6")


class PreflightFailure(PreflightError):
    """A preflight guard failed; ``steps`` holds every step run so far."""

    def __init__(self, message: str, *, steps: list[StepResult]) -> None:
        super().__init__(message)
        self.steps = steps


class _GuardFail(Exception):
    """Internal: a guard found an unsafe or unusable condition."""


def parse_tags(value: str) -> list[str]:
    """Split a PVE ``tags`` string (``;``, ``,`` or space separated)."""
    return [t for t in re.split(r"[;,\s]+", value or "") if t]


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _version(api: PveApi, cfg: Config) -> str:
    v = api.version()
    return f"PVE {v.get('version', '?')} (release {v.get('release', '?')})"


def _node(api: PveApi, cfg: Config) -> str:
    want = cfg.target.node
    if api.node != want:
        raise _GuardFail(f"API client is bound to node {api.node!r}, config says {want!r}")
    nodes = [e for e in api.cluster_status() if e.get("type") == "node"]
    match = [e for e in nodes if e.get("name") == want]
    if not match:
        names = ", ".join(sorted(str(e.get("name")) for e in nodes)) or "none"
        raise _GuardFail(f"node {want!r} not found (nodes: {names})")
    if "local" in match[0] and not _truthy(match[0]["local"]):
        local = [str(e.get("name")) for e in nodes if _truthy(e.get("local", 0))]
        raise _GuardFail(f"the API is served by node {', '.join(local) or '?'}, not {want!r}")
    return f"node {want} ok"


def _standalone(api: PveApi, cfg: Config) -> str:
    clusters = [str(e.get("name", "")) for e in api.cluster_status() if e.get("type") == "cluster"]
    if not clusters:
        return "standalone node"
    name = clusters[0]
    if cfg.target.require_standalone:
        raise _GuardFail(f"node is a member of cluster {name!r}; refusing (target.require_standalone = true)")
    if name in cfg.target.forbid_cluster_names:
        raise _GuardFail(f"cluster {name!r} is listed in target.forbid_cluster_names")
    log.warning("PREFLIGHT_CLUSTERED cluster=%s (allowed by config)", name)
    return f"clustered in {name!r} (allowed by config)"


def _bridge(api: PveApi, cfg: Config) -> str:
    want = cfg.restore.isolated_bridge
    match = [n for n in api.node_networks() if n.get("iface") == want]
    if not match:
        raise _GuardFail(f"bridge {want!r} does not exist on the node")
    br = match[0]
    if br.get("type") != "bridge":
        raise _GuardFail(f"{want!r} has type {br.get('type')!r}, expected 'bridge'")
    if not cfg.restore.require_isolated_bridge:
        return f"bridge {want} exists (isolation not enforced)"
    ports = str(br.get("bridge_ports") or "").strip()
    if ports and ports.lower() != "none":
        raise _GuardFail(f"bridge {want!r} has ports ({ports}); it must not be connected to any NIC")
    addrs = [f"{f}={br[f]}" for f in _IP_FIELDS if str(br.get(f) or "").strip()]
    if addrs:
        raise _GuardFail(f"bridge {want!r} has an IP configuration ({', '.join(addrs)}); it must be isolated")
    return f"bridge {want} is isolated (no ports, no IP)"


def _storage(api: PveApi, name: str) -> dict[str, Any]:
    for s in api.storage_list():
        if s.get("storage") == name:
            if not _truthy(s.get("enabled", 0)) or not _truthy(s.get("active", 0)):
                raise _GuardFail(f"storage {name!r} is not active and enabled")
            return s
    raise _GuardFail(f"storage {name!r} does not exist on the node")


def _backup_storage(api: PveApi, cfg: Config) -> str:
    name = cfg.restore.backup_storage
    s = _storage(api, name)
    if s.get("type") != "pbs":
        raise _GuardFail(f"backup storage {name!r} has type {s.get('type')!r}, expected 'pbs'")
    return f"backup storage {name} (pbs) active"


def _target_storage(api: PveApi, cfg: Config) -> str:
    name = cfg.restore.target_storage
    s = _storage(api, name)
    content = [c.strip() for c in str(s.get("content", "")).split(",")]
    if "images" not in content:
        raise _GuardFail(f"target storage {name!r} does not allow content 'images'")
    return f"target storage {name} active, content images"


def _temp_range(api: PveApi, cfg: Config) -> str:
    base = cfg.restore.temp_vmid_base
    foreign = sorted(
        int(v["vmid"])
        for v in api.list_vms()
        if cfg.is_temp_vmid(int(v["vmid"])) and cfg.restore.tag not in parse_tags(str(v.get("tags", "")))
    )
    if foreign:
        raise _GuardFail(
            f"untagged VM(s) {', '.join(map(str, foreign))} in the temp VMID range "
            f"[{base + 100}, {2 * base}); cleanup could never remove them"
        )
    return f"temp VMID range [{base + 100}, {2 * base}) is free of foreign VMs"


_GUARDS: tuple[tuple[str, Callable[[PveApi, Config], str]], ...] = (
    ("version", _version),
    ("node", _node),
    ("standalone", _standalone),
    ("bridge", _bridge),
    ("backup_storage", _backup_storage),
    ("target_storage", _target_storage),
    ("temp_range", _temp_range),
)


def preflight(api: PveApi, cfg: Config) -> list[StepResult]:
    """Run every guard; raise :class:`PreflightFailure` at the first failure."""
    steps: list[StepResult] = []
    for name, guard in _GUARDS:
        t0 = time.monotonic()
        started = utc_now_iso()
        status, message = Status.PASS, ""
        try:
            message = guard(api, cfg)
        except _GuardFail as exc:
            status, message = Status.FAIL, str(exc)
        except ApiError as exc:
            status, message = Status.ERROR, f"API error: {exc}"
        failed = status is not Status.PASS
        steps.append(
            StepResult(
                name=name,
                status=status,
                started_at=started,
                duration_s=round(time.monotonic() - t0, 3),
                message=message,
                error_code=PreflightError.code if failed else "",
            )
        )
        if failed:
            log.error("PREFLIGHT_FAIL step=%s reason=%s", name, message)
            raise PreflightFailure(f"preflight {name}: {message}", steps=steps)
        log.info("PREFLIGHT_OK step=%s %s", name, message)
    return steps
