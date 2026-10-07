"""Pure VM-config sanitizer (SPEC §3).

:func:`sanitize_config` turns a restored VM's raw PVE config into ONE
``update_vm_config(set, delete)`` call that isolates the VM (network on the
isolated bridge, no passthrough, no host devices) and makes it bootable on the
restore node. It performs no I/O and is unit-tested exhaustively.

:func:`split_privileged` then divides that plan into the part an API token
may apply and the root-only part applied through ``NodeShell.qm_set``
(SPEC §1a).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import NamedTuple

from pbv.config import SanitizeConfig

PRIVILEGED_KEY = re.compile(r"^(?:(?:hostpci|usb|serial|parallel|virtiofs)\d+|args|hookscript)$")
"""Config keys PVE 9 may restrict to root@pam (mirror of ``pbv.testing.fakes.PRIVILEGED_KEY``)."""

_NET = re.compile(r"net\d+")
_PASSTHROUGH = re.compile(r"(hostpci|usb|parallel|virtiofs)\d+")
_SERIAL = re.compile(r"serial\d+")
_DRIVE = re.compile(r"(ide|sata|scsi|virtio)\d+")
_OTHER_DISK = re.compile(r"efidisk0|tpmstate0|unused\d+")
_CDROM_BUS = re.compile(r"(ide|sata|scsi)\d+")
_CLOUDINIT = re.compile(r"(^|[:/])vm-\d+-cloudinit")
_NET_DROP = ("tag", "trunks", "rate", "link_down")
_HOST_SPECIFIC = ("affinity", "args", "hookscript", "hugepages", "startup")
_FALSY = {"0", "no", "off", "false"}


@dataclass(frozen=True)
class SanitizePlan:
    """Result of :func:`sanitize_config`; ``set`` and ``delete`` never overlap."""

    set: dict[str, str] = field(default_factory=dict)
    delete: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _opts(value: str) -> list[str]:
    return [p for p in value.split(",") if p]


def _opt_key(part: str) -> str:
    return part.split("=", 1)[0] if "=" in part else ""


def _volume(value: str) -> str:
    """The volume of a drive value (first positional option or ``file=``)."""
    for i, part in enumerate(_opts(value)):
        if part.startswith("file="):
            return part[len("file=") :]
        if i == 0 and "=" not in part:
            return part
    return ""


def _sanitize_net(key: str, value: str, bridge: str) -> tuple[str, str]:
    parts = _opts(value)
    changes: list[str] = []
    out: list[str] = []
    seen_bridge = seen_fw = False
    for part in parts:
        k = _opt_key(part)
        if k == "bridge":
            seen_bridge = True
            old = part.split("=", 1)[1]
            if old != bridge:
                changes.append(f"bridge {old} → {bridge}")
            out.append(f"bridge={bridge}")
        elif k == "firewall":
            seen_fw = True
            if part != "firewall=0":
                changes.append("firewall off")
            out.append("firewall=0")
        elif k in _NET_DROP:
            changes.append(f"removed {part}")
        else:
            out.append(part)
    if not seen_bridge:
        out.append(f"bridge={bridge}")
        changes.append(f"bridge (none) → {bridge}")
    if not seen_fw:
        out.append("firewall=0")
    new = ",".join(out)
    if new == value:
        return value, ""
    return new, f"{key}: " + (", ".join(changes) if changes else "isolated")


def _sanitize_agent(value: str) -> str | None:
    """New ``agent`` value, or None when the agent is already enabled."""
    parts = _opts(value)
    if not parts:
        return "1"
    if "=" not in parts[0]:
        if parts[0].lower() in _FALSY:
            return ",".join(["1", *parts[1:]])
        return None
    for i, part in enumerate(parts):
        if _opt_key(part) == "enabled":
            if part.split("=", 1)[1].lower() in _FALSY:
                return ",".join([*parts[:i], "enabled=1", *parts[i + 1 :]])
            return None
    return ",".join(["enabled=1", *parts])  # PVE default is enabled=0


def _mib(value: str) -> int | None:
    first = (_opts(value) or [""])[0]
    if first.startswith("current="):
        first = first[len("current=") :]
    try:
        return int(first)
    except ValueError:
        return None


def sanitize_config(
    cfg: Mapping[str, str],
    *,
    bridge: str,
    storages: set[str],
    opts: SanitizeConfig,
    vmid: int,
) -> SanitizePlan:
    """Compute the config changes that isolate restored VM ``vmid`` (SPEC §3).

    ``storages`` are the storage names present on the restore node; disks on
    any other storage are removed with a warning. ``notes`` and ``warnings``
    are sorted by config key.
    """
    set_: dict[str, str] = {}
    delete: list[str] = []
    notes: list[tuple[str, str]] = []
    warnings: list[tuple[str, str]] = []

    def drop(key: str, note: str, *, warn: bool = False) -> None:
        delete.append(key)
        (warnings if warn else notes).append((key, f"{key}: {note}"))

    for key in sorted(cfg):
        value = cfg[key]
        if _NET.fullmatch(key):
            new, note = _sanitize_net(key, value, bridge)
            if note:
                set_[key] = new
                notes.append((key, note))
        elif _PASSTHROUGH.fullmatch(key):
            drop(key, f"removed passthrough ({value})")
        elif _SERIAL.fullmatch(key):
            if not (opts.keep_serial and value == "socket"):
                drop(key, f"removed host serial device {value}")
        elif _CDROM_BUS.fullmatch(key) and "media=cdrom" in _opts(value):
            vol = _volume(value)
            if vol not in ("", "none", "cdrom") and not _CLOUDINIT.search(vol):
                set_[key] = "none,media=cdrom"
                notes.append((key, f"{key}: ejected ISO {vol}"))
        elif _DRIVE.fullmatch(key) or _OTHER_DISK.fullmatch(key):
            vol = _volume(value)
            if vol.startswith("/"):
                drop(key, f"raw device {vol} removed", warn=True)
            elif ":" in vol and vol.split(":", 1)[0] not in storages:
                drop(key, f"disk on missing storage {vol.split(':', 1)[0]} removed", warn=True)
        elif key in _HOST_SPECIFIC:
            drop(key, f"removed host-specific option ({value})")

    if cfg.get("onboot", "0") != "0":
        set_["onboot"] = "0"
        notes.append(("onboot", "onboot: set to 0"))

    agent = _sanitize_agent(cfg.get("agent", ""))
    if agent is not None:
        set_["agent"] = agent
        notes.append(("agent", "agent: enabled guest agent"))

    if opts.cpu_override and cfg.get("cpu", "") != opts.cpu_override:
        set_["cpu"] = opts.cpu_override
        notes.append(("cpu", f"cpu: {cfg.get('cpu') or '(default)'} → {opts.cpu_override}"))

    if opts.memory_max_mib > 0:
        cap = opts.memory_max_mib
        mem = _mib(cfg.get("memory", "")) if "memory" in cfg else None
        if mem is not None and mem > cap:
            set_["memory"] = str(cap)
            notes.append(("memory", f"memory: {mem} → {cap} MiB"))
        balloon = _mib(cfg.get("balloon", "")) if "balloon" in cfg else None
        if balloon is not None and balloon > cap:
            set_["balloon"] = str(cap)
            notes.append(("balloon", f"balloon: {balloon} → {cap} MiB"))

    if opts.vga and cfg.get("vga", "") != opts.vga:
        set_["vga"] = opts.vga
        notes.append(("vga", f"vga: {cfg.get('vga') or '(default)'} → {opts.vga}"))

    delete = sorted(k for k in set(delete) if k not in set_)
    return SanitizePlan(
        set=set_,
        delete=delete,
        notes=[n for _, n in sorted(notes, key=lambda kn: kn[0])],
        warnings=[w for _, w in sorted(warnings, key=lambda kn: kn[0])],
    )


class PrivilegedSplit(NamedTuple):
    """A :class:`SanitizePlan` split into the API part and the root-only ``qm set`` part (SPEC §1a)."""

    api_set: dict[str, str]
    api_delete: list[str]
    root_set: dict[str, str]
    root_delete: list[str]

    @property
    def root_keys(self) -> list[str]:
        return sorted({*self.root_set, *self.root_delete})


def _host_device(value: str) -> str:
    """The ``host=`` of a hostpci/usb value (also the positional first option), else ``""``."""
    for i, part in enumerate(_opts(value)):
        if part.startswith("host="):
            return part[len("host=") :]
        if i == 0 and "=" not in part:
            return part
    return ""


def _needs_root(key: str, old: str | None, new: str | None) -> bool:
    """True if a token (never root@pam) cannot change ``key`` from ``old`` to ``new`` (None = absent)."""
    if not PRIVILEGED_KEY.match(key):
        return False
    if _SERIAL.fullmatch(key):
        return old not in (None, "socket") or new not in (None, "socket")
    if key.startswith(("hostpci", "usb")):
        # Mapped devices only need Mapping.Use; USB spice is a plain HWType change.
        hosts = {_host_device(v) for v in (old, new) if v is not None} - {""}
        return bool(hosts - ({"spice"} if key.startswith("usb") else set()))
    return True


def split_privileged(plan: SanitizePlan, current_cfg: Mapping[str, str], *, have_root: bool = True) -> PrivilegedSplit:
    """Split ``plan`` into API keys and root-only keys (SPEC §1a).

    With ``have_root`` (a NodeShell is configured) every key matching
    :data:`PRIVILEGED_KEY` goes to root, except ``serial*`` that stays a
    ``socket`` (the API allows it and needs no root shell). Without it, only
    keys the API is known to refuse go to root: non-mapped ``hostpci``/``usb``
    (``host=``), real-device serials, ``parallel*``, ``virtiofs*``, ``args``
    and ``hookscript``; mapped devices are still tried via the API.
    """

    def root(key: str, new: str | None) -> bool:
        if have_root and PRIVILEGED_KEY.match(key) and not _SERIAL.fullmatch(key):
            return True
        return _needs_root(key, current_cfg.get(key), new)

    out = PrivilegedSplit({}, [], {}, [])
    for key, value in plan.set.items():
        (out.root_set if root(key, value) else out.api_set)[key] = value
    for key in plan.delete:
        (out.root_delete if root(key, None) else out.api_delete).append(key)
    return out
