"""TOML configuration loading and validation (frozen contract, owned by the architect).

``load_config(path)`` returns a fully validated, immutable :class:`Config`.
All validation errors raise :class:`pbv.core.ConfigError` with a message that
names the offending key (``vm[2].check[0].port``). Secrets are only accepted
via ``*_file`` / ``*_env`` indirection, never inline, and are kept out of
``repr``.
"""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from pbv.core import CheckSpec, ConfigError, NotifyWhen, OsFamily, VmTarget

MAX_VMID = 999_999_999
MAX_SCRIPT_BYTES = 60_000  # PVE agent file-write / input-data limit is ~64 KiB
MODES = ("auto", "hybrid", "manual")

# ──────────────────────────────────────────────────────────────────────────────
# Config dataclasses
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TargetConfig:
    host: str
    node: str
    token_id: str
    token_secret: str = field(repr=False)
    port: int = 8006
    verify_tls: bool = True
    ca_file: str = ""
    fingerprint: str = ""  # normalized: lowercase hex, no colons ("" = no pinning)
    require_standalone: bool = True
    forbid_cluster_names: tuple[str, ...] = ()
    api_timeout_s: int = 30
    api_retries: int = 3


@dataclass(frozen=True)
class RestoreConfig:
    backup_storage: str
    target_storage: str
    isolated_bridge: str
    require_isolated_bridge: bool = True
    temp_vmid_base: int = 900_000
    tag: str = "pbv-temp"
    pool: str = ""
    bwlimit_kib: int = 0
    restore_timeout_s: int = 3600
    min_free_space_ratio: float = 1.1
    max_backup_age_h: int = 0  # 0 disables the staleness check
    keep_on_failure: bool = False


@dataclass(frozen=True)
class SanitizeConfig:
    cpu_override: str = ""  # e.g. "x86-64-v2-AES" when the target CPU differs
    memory_max_mib: int = 0  # 0 = keep original memory
    vga: str = ""  # e.g. "std" to guarantee a screenshot-able framebuffer
    keep_serial: bool = True


@dataclass(frozen=True)
class RunConfig:
    log_dir: Path = Path("/var/log/pbv")
    state_dir: Path = Path("/var/lib/pbv")
    lock_file: Path = Path("/run/lock/pbv.lock")
    boot_timeout_s: int = 300
    settle_s: int = 10
    default_check_timeout_s: int = 60
    sweep_leftovers: bool = True
    fail_on_warn: bool = False
    selection: str = "listed"  # "listed" | "all"
    exclude: tuple[int, ...] = ()
    default_mode: str = "auto"


@dataclass(frozen=True)
class NodeShellConfig:
    """Root shell on the restore node for root@pam-only operations (see core.NodeShell)."""

    mode: str = "off"  # "off" | "local" (pbv runs on the restore node as root) | "ssh"
    ssh_host: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key_file: str = ""
    ssh_known_hosts_file: str = ""
    remote_dir: str = "/var/lib/pbv/screendump"  # where screendump writes on the node
    timeout_s: int = 60


@dataclass(frozen=True)
class ScreenshotConfig:
    enabled: bool = False  # requires node_shell.mode != "off" (screendump is root-only in PVE 9)
    when: str = "failure"  # "failure" | "always"


@dataclass(frozen=True)
class EmailConfig:
    enabled: bool = False
    when: NotifyWhen = NotifyWhen.FAILURE
    per_vm: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    security: str = "starttls"  # "starttls" | "ssl" | "none"
    username: str = ""
    password: str = field(default="", repr=False)
    sender: str = ""
    to: tuple[str, ...] = ()
    subject_prefix: str = "[pbv]"
    attach_screenshots: bool = True
    timeout_s: int = 30


@dataclass(frozen=True)
class NtfyConfig:
    enabled: bool = False
    when: NotifyWhen = NotifyWhen.FAILURE
    per_vm: bool = False
    server: str = "https://ntfy.sh"
    topic: str = ""
    token: str = field(default="", repr=False)
    priority_ok: str = "default"
    priority_fail: str = "high"
    tags_ok: tuple[str, ...] = ("white_check_mark",)
    tags_fail: tuple[str, ...] = ("rotating_light",)
    click_url: str = ""
    attach_screenshots: bool = False
    timeout_s: int = 15


@dataclass(frozen=True)
class JsonConfig:
    enabled: bool = True
    when: NotifyWhen = NotifyWhen.ALWAYS
    dir: Path = Path("/var/lib/pbv/reports")
    write_latest: bool = True  # also write <dir>/latest.json
    stdout: bool = False
    keep: int = 90  # number of report files to keep (0 = unlimited)


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool = False
    when: NotifyWhen = NotifyWhen.FAILURE
    per_vm: bool = False
    token: str = field(default="", repr=False)
    chat_id: str = ""
    thread_id: str = ""
    timeout_s: int = 15


@dataclass(frozen=True)
class NotifyConfig:
    email: EmailConfig = EmailConfig()
    ntfy: NtfyConfig = NtfyConfig()
    json: JsonConfig = JsonConfig()
    telegram: TelegramConfig = TelegramConfig()


@dataclass(frozen=True)
class Config:
    path: Path
    config_dir: Path
    target: TargetConfig
    restore: RestoreConfig
    sanitize: SanitizeConfig
    run: RunConfig
    node_shell: NodeShellConfig
    screenshot: ScreenshotConfig
    notify: NotifyConfig
    vms: tuple[VmTarget, ...]
    global_checks: tuple[CheckSpec, ...]

    def temp_vmid(self, vmid: int) -> int:
        return self.restore.temp_vmid_base + vmid

    def is_temp_vmid(self, vmid: int) -> bool:
        base = self.restore.temp_vmid_base
        return base + 100 <= vmid < 2 * base and vmid <= MAX_VMID

    def vm_target(self, vmid: int) -> VmTarget:
        """Target for ``vmid``: the configured entry, or a default auto entry
        (used by ``selection = "all"`` and ``--vmid`` for unlisted VMs)."""
        for vm in self.vms:
            if vm.vmid == vmid:
                return vm
        _check_source_vmid(vmid, self.restore.temp_vmid_base, f"vmid {vmid}")
        return VmTarget(
            vmid=vmid,
            temp_vmid=self.temp_vmid(vmid),
            mode=self.run.default_mode,
            os=None,
            checks=(),
            boot_timeout_s=self.run.boot_timeout_s,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Check type schemas
# ──────────────────────────────────────────────────────────────────────────────

# Per check type: key -> (python type(s), required, default). Common keys
# (type, name, critical, timeout_s, wait_s, os) are handled separately.
_STR, _INT, _BOOL, _LIST_STR, _LIST_INT, _MAP = str, int, bool, "list[str]", "list[int]", "map[str,str]"

CHECK_TYPES: dict[str, dict[str, tuple[Any, bool, Any]]] = {
    "systemd": {"unit": (_STR, True, None)},
    "windows_service": {"service": (_STR, True, None)},
    "tcp_listen": {"port": (_INT, True, None)},
    "http": {
        "port": (_INT, True, None),
        "scheme": (_STR, False, "http"),
        "path": (_STR, False, "/"),
        "host": (_STR, False, "127.0.0.1"),
        "expect_status": (_LIST_INT, False, None),  # None = 2xx/3xx/401/403
        "body_regex": (_STR, False, ""),
    },
    "command": {
        "argv": (_LIST_STR, True, None),
        "expect_exit": (_LIST_INT, False, [0]),
        "warn_exit": (_LIST_INT, False, []),
        "stdout_regex": (_STR, False, ""),
    },
    "script": {
        "path": (_STR, True, None),
        "interpreter": (_STR, False, ""),  # "" = by OS: /bin/sh or powershell
        "args": (_LIST_STR, False, []),
        "env": (_MAP, False, {}),
        "expect_exit": (_LIST_INT, False, [0]),
        "warn_exit": (_LIST_INT, False, []),
        "stdout_regex": (_STR, False, ""),
    },
    "host_script": {
        "path": (_STR, True, None),
        "args": (_LIST_STR, False, []),
        "env": (_MAP, False, {}),
        "expect_exit": (_LIST_INT, False, [0]),
        "warn_exit": (_LIST_INT, False, []),
    },
    "log_scan": {
        "unit": (_STR, True, None),
        "since": (_STR, False, "5 min ago"),
        "error_regex": (_STR, False, r"(?i)\b(error|fatal|failed)\b"),
        "ignore_regex": (_STR, False, ""),
        "max_matches": (_INT, False, 0),
    },
}

_COMMON_CHECK_KEYS = {"type", "name", "critical", "timeout_s", "wait_s", "os"}
_MAIN_PARAM = {
    "systemd": "unit",
    "windows_service": "service",
    "tcp_listen": "port",
    "http": "port",
    "command": "argv",
    "script": "path",
    "host_script": "path",
    "log_scan": "unit",
}
_LINUX_ONLY = {"systemd", "log_scan"}
_WINDOWS_ONLY = {"windows_service"}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


class _Section:
    """Typed accessor over one TOML table that reports unknown keys."""

    def __init__(self, data: Any, where: str) -> None:
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(f"{where}: expected a table")
        self.data: dict[str, Any] = data
        self.where = where
        self.used: set[str] = set()

    def _get(self, key: str, default: Any, required: bool) -> Any:
        self.used.add(key)
        if key not in self.data:
            if required:
                raise ConfigError(f"{self.where}.{key}: required")
            return default
        return self.data[key]

    def str(self, key: str, default: str = "", *, required: bool = False, choices: tuple[str, ...] = ()) -> str:
        v = self._get(key, default, required)
        if not isinstance(v, str):
            raise ConfigError(f"{self.where}.{key}: expected a string")
        if required and not v.strip():
            raise ConfigError(f"{self.where}.{key}: must not be empty")
        if choices and v not in choices:
            raise ConfigError(f"{self.where}.{key}: must be one of {', '.join(choices)} (got {v!r})")
        return v

    def int(
        self, key: str, default: int = 0, *, required: bool = False, lo: int | None = None, hi: int | None = None
    ) -> int:
        v = self._get(key, default, required)
        if isinstance(v, bool) or not isinstance(v, int):
            raise ConfigError(f"{self.where}.{key}: expected an integer")
        if lo is not None and v < lo:
            raise ConfigError(f"{self.where}.{key}: must be >= {lo}")
        if hi is not None and v > hi:
            raise ConfigError(f"{self.where}.{key}: must be <= {hi}")
        return v

    def float(self, key: str, default: float, *, lo: float | None = None) -> float:
        v = self._get(key, default, False)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ConfigError(f"{self.where}.{key}: expected a number")
        if lo is not None and v < lo:
            raise ConfigError(f"{self.where}.{key}: must be >= {lo}")
        return float(v)

    def bool(self, key: str, default: bool) -> bool:
        v = self._get(key, default, False)
        if not isinstance(v, bool):
            raise ConfigError(f"{self.where}.{key}: expected true or false")
        return v

    def str_list(self, key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        v = self._get(key, list(default), False)
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ConfigError(f"{self.where}.{key}: expected a list of strings")
        return tuple(v)

    def int_list(self, key: str, default: tuple[int, ...] = ()) -> tuple[int, ...]:
        v = self._get(key, list(default), False)
        if not isinstance(v, list) or not all(isinstance(x, int) and not isinstance(x, bool) for x in v):
            raise ConfigError(f"{self.where}.{key}: expected a list of integers")
        return tuple(v)

    def table(self, key: str) -> _Section:
        return _Section(self._get(key, {}, False), f"{self.where}.{key}")

    def secret(self, key: str, base_dir: Path, *, required: bool = False) -> str:
        """Resolve ``<key>_file`` or ``<key>_env``; inline ``<key>`` is rejected."""
        self.used.update({key, f"{key}_file", f"{key}_env"})
        if key in self.data:
            raise ConfigError(f"{self.where}.{key}: inline secrets are not allowed; use {key}_file or {key}_env")
        f, e = self.data.get(f"{key}_file", ""), self.data.get(f"{key}_env", "")
        if not isinstance(f, str) or not isinstance(e, str):
            raise ConfigError(f"{self.where}.{key}_file/{key}_env: expected strings")
        if f and e:
            raise ConfigError(f"{self.where}: set only one of {key}_file and {key}_env")
        if f:
            p = _resolve(base_dir, f)
            try:
                value = p.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ConfigError(f"{self.where}.{key}_file: cannot read {p}: {exc.strerror}") from None
            try:
                world_readable = bool(p.stat().st_mode & stat.S_IROTH)
            except OSError:
                world_readable = False
            if world_readable:
                raise ConfigError(f"{self.where}.{key}_file: {p} is world-readable; chmod 600 it")
        elif e:
            value = os.environ.get(e, "").strip()
            if not value:
                raise ConfigError(f"{self.where}.{key}_env: environment variable {e} is empty or unset")
        else:
            value = ""
        if required and not value:
            raise ConfigError(f"{self.where}: {key}_file or {key}_env is required")
        return value

    def finish(self) -> None:
        unknown = sorted(set(self.data) - self.used)
        if unknown:
            raise ConfigError(f"{self.where}: unknown key(s): {', '.join(unknown)}")


def _resolve(base: Path, p: str) -> Path:
    path = Path(p).expanduser()
    return path if path.is_absolute() else (base / path)


def _when(s: _Section, default: NotifyWhen) -> NotifyWhen:
    return NotifyWhen(s.str("when", default.value, choices=tuple(w.value for w in NotifyWhen)))


def _check_source_vmid(vmid: int, base: int, where: str) -> None:
    if not 100 <= vmid < base:
        raise ConfigError(f"{where}: VMID {vmid} must be between 100 and temp_vmid_base-1 ({base - 1})")


def normalize_fingerprint(fp: str) -> str:
    h = fp.replace(":", "").strip().lower()
    if h and not re.fullmatch(r"[0-9a-f]{64}", h):
        raise ConfigError("target.fingerprint: expected a SHA-256 fingerprint (64 hex digits, colons optional)")
    return h


# ──────────────────────────────────────────────────────────────────────────────
# Checks
# ──────────────────────────────────────────────────────────────────────────────


def parse_check(raw: Any, where: str, *, config_dir: Path, default_timeout: int, source: str) -> CheckSpec:
    s = _Section(raw, where)
    ctype = s.str("type", required=True, choices=tuple(CHECK_TYPES))
    schema = CHECK_TYPES[ctype]
    params: dict[str, Any] = {}
    for key, (typ, required, default) in schema.items():
        if typ is _STR:
            params[key] = s.str(key, default if default is not None else "", required=required)
        elif typ is _INT:
            params[key] = s.int(key, default if default is not None else 0, required=required)
        elif typ == _LIST_STR:
            if required and key not in s.data:
                raise ConfigError(f"{where}.{key}: required")
            params[key] = list(s.str_list(key, tuple(default or ())))
        elif typ == _LIST_INT:
            if key in s.data or default is not None:
                params[key] = list(s.int_list(key, tuple(default or ())))
            else:
                s.used.add(key)
                params[key] = None
        elif typ == _MAP:
            env = s._get(key, {}, False)
            if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
                raise ConfigError(f"{where}.{key}: expected a table of string values")
            params[key] = dict(env)
    if ctype in ("tcp_listen", "http") and not 1 <= params["port"] <= 65535:
        raise ConfigError(f"{where}.port: must be 1-65535")
    if ctype == "http":
        if params["scheme"] not in ("http", "https"):
            raise ConfigError(f"{where}.scheme: must be http or https")
        if not params["path"].startswith("/"):
            raise ConfigError(f"{where}.path: must start with /")
    if ctype == "command" and not params["argv"]:
        raise ConfigError(f"{where}.argv: must not be empty")
    for key in ("stdout_regex", "body_regex", "error_regex", "ignore_regex"):
        if params.get(key):
            try:
                re.compile(params[key])
            except re.error as exc:
                raise ConfigError(f"{where}.{key}: invalid regex: {exc}") from None
    if ctype in ("script", "host_script"):
        p = _resolve(config_dir, params["path"])
        if not p.is_file():
            raise ConfigError(f"{where}.path: script not found: {p}")
        if ctype == "script" and p.stat().st_size > MAX_SCRIPT_BYTES:
            raise ConfigError(f"{where}.path: guest scripts are limited to {MAX_SCRIPT_BYTES} bytes")
        if ctype == "host_script" and not os.access(p, os.X_OK):
            raise ConfigError(f"{where}.path: host script is not executable: {p}")
        params["path"] = str(p.resolve())

    os_name = s.str("os", "any", choices=("any", "linux", "windows"))
    only_os = None if os_name == "any" else OsFamily(os_name)
    if ctype in _LINUX_ONLY:
        only_os = only_os or OsFamily.LINUX
    if ctype in _WINDOWS_ONLY:
        only_os = only_os or OsFamily.WINDOWS
    main = params[_MAIN_PARAM[ctype]]
    if isinstance(main, list):
        main = " ".join(main)
    if ctype in ("script", "host_script"):
        main = Path(main).name
    spec = CheckSpec(
        type=ctype,
        name=s.str("name", f"{ctype}:{main}") or f"{ctype}:{main}",
        params=params,
        critical=s.bool("critical", True),
        timeout_s=s.int("timeout_s", default_timeout, lo=1, hi=86_400),
        wait_s=s.int("wait_s", 0, lo=0, hi=86_400),
        source=source,
        only_os=only_os,
    )
    s.finish()
    return spec


# ──────────────────────────────────────────────────────────────────────────────
# Loader
# ──────────────────────────────────────────────────────────────────────────────


def load_config(path: str | os.PathLike[str]) -> Config:
    p = Path(path).expanduser()
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {p}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config {p}: {exc.strerror}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{p}: invalid TOML: {exc}") from None
    return parse_config(raw, p)


def parse_config(raw: Mapping[str, Any], path: Path) -> Config:
    path = Path(path).absolute()
    base = path.parent
    root = _Section(dict(raw), "config")
    root.where = ""  # top-level keys print as ".target" otherwise

    def sect(name: str) -> _Section:
        s = root.table(name)
        s.where = name
        return s

    # target
    t = sect("target")
    fp = normalize_fingerprint(t.str("fingerprint", ""))
    target = TargetConfig(
        host=t.str("host", required=True),
        node=t.str("node", required=True),
        token_id=t.str("token_id", required=True),
        token_secret=t.secret("token_secret", base, required=True),
        port=t.int("port", 8006, lo=1, hi=65535),
        verify_tls=t.bool("verify_tls", True),
        ca_file=str(_resolve(base, c)) if (c := t.str("ca_file", "")) else "",
        fingerprint=fp,
        require_standalone=t.bool("require_standalone", True),
        forbid_cluster_names=t.str_list("forbid_cluster_names"),
        api_timeout_s=t.int("api_timeout_s", 30, lo=1, hi=600),
        api_retries=t.int("api_retries", 3, lo=0, hi=10),
    )
    if not re.fullmatch(r"[^@!\s]+@[^@!\s]+![A-Za-z0-9][A-Za-z0-9._-]*", target.token_id):
        raise ConfigError("target.token_id: expected an API token id like 'pbv@pve!validation'")
    t.finish()

    # restore
    r = sect("restore")
    restore = RestoreConfig(
        backup_storage=r.str("backup_storage", required=True),
        target_storage=r.str("target_storage", required=True),
        isolated_bridge=r.str("isolated_bridge", required=True),
        require_isolated_bridge=r.bool("require_isolated_bridge", True),
        temp_vmid_base=r.int("temp_vmid_base", 900_000, lo=1000, hi=MAX_VMID // 2),
        tag=r.str("tag", "pbv-temp"),
        pool=r.str("pool", ""),
        bwlimit_kib=r.int("bwlimit_kib", 0, lo=0),
        restore_timeout_s=r.int("restore_timeout_s", 3600, lo=60),
        min_free_space_ratio=r.float("min_free_space_ratio", 1.1, lo=0.0),
        max_backup_age_h=r.int("max_backup_age_h", 0, lo=0),
        keep_on_failure=r.bool("keep_on_failure", False),
    )
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.+-]*", restore.tag):
        raise ConfigError("restore.tag: PVE tags must be lowercase letters, digits, and _.+-")
    r.finish()

    s = sect("sanitize")
    sanitize = SanitizeConfig(
        cpu_override=s.str("cpu_override", ""),
        memory_max_mib=s.int("memory_max_mib", 0, lo=0),
        vga=s.str("vga", ""),
        keep_serial=s.bool("keep_serial", True),
    )
    s.finish()

    ru = sect("run")
    run = RunConfig(
        log_dir=_resolve(base, ru.str("log_dir", "/var/log/pbv")),
        state_dir=_resolve(base, ru.str("state_dir", "/var/lib/pbv")),
        lock_file=_resolve(base, ru.str("lock_file", "/run/lock/pbv.lock")),
        boot_timeout_s=ru.int("boot_timeout_s", 300, lo=10),
        settle_s=ru.int("settle_s", 10, lo=0),
        default_check_timeout_s=ru.int("default_check_timeout_s", 60, lo=1),
        sweep_leftovers=ru.bool("sweep_leftovers", True),
        fail_on_warn=ru.bool("fail_on_warn", False),
        selection=ru.str("selection", "listed", choices=("listed", "all")),
        exclude=ru.int_list("exclude"),
        default_mode=ru.str("default_mode", "auto", choices=MODES),
    )
    ru.finish()

    ns = sect("node_shell")
    node_shell = NodeShellConfig(
        mode=ns.str("mode", "off", choices=("off", "local", "ssh")),
        ssh_host=ns.str("ssh_host", ""),
        ssh_user=ns.str("ssh_user", "root"),
        ssh_port=ns.int("ssh_port", 22, lo=1, hi=65535),
        ssh_key_file=str(_resolve(base, k)) if (k := ns.str("ssh_key_file", "")) else "",
        ssh_known_hosts_file=str(_resolve(base, k)) if (k := ns.str("ssh_known_hosts_file", "")) else "",
        remote_dir=ns.str("remote_dir", "/var/lib/pbv/screendump"),
        timeout_s=ns.int("timeout_s", 60, lo=5, hi=3600),
    )
    if node_shell.mode == "ssh" and not node_shell.ssh_host:
        raise ConfigError('node_shell.ssh_host: required when mode = "ssh"')
    if not node_shell.remote_dir.startswith("/"):
        raise ConfigError("node_shell.remote_dir: must be an absolute path on the restore node")
    ns.finish()

    sc = sect("screenshot")
    shot = ScreenshotConfig(
        enabled=sc.bool("enabled", False),
        when=sc.str("when", "failure", choices=("failure", "always")),
    )
    if shot.enabled and node_shell.mode == "off":
        raise ConfigError('screenshot.enabled: needs node_shell.mode = "local" or "ssh" (screendump is root-only)')
    sc.finish()

    notify = _parse_notify(sect("notify"), base)

    # global checks
    gl = root._get("global_check", [], False)
    if not isinstance(gl, list):
        raise ConfigError("global_check: expected an array of tables ([[global_check]])")
    global_checks = tuple(
        parse_check(
            c, f"global_check[{i}]", config_dir=base, default_timeout=run.default_check_timeout_s, source="global"
        )
        for i, c in enumerate(gl)
    )

    # VMs
    vl = root._get("vm", [], False)
    if not isinstance(vl, list):
        raise ConfigError("vm: expected an array of tables ([[vm]])")
    vms: list[VmTarget] = []
    seen: set[int] = set()
    for i, rv in enumerate(vl):
        where = f"vm[{i}]"
        v = _Section(rv, where)
        vmid = v.int("vmid", required=True)
        _check_source_vmid(vmid, restore.temp_vmid_base, f"{where}.vmid")
        if vmid in seen:
            raise ConfigError(f"{where}.vmid: duplicate VMID {vmid}")
        seen.add(vmid)
        os_name = v.str("os", "", choices=("", "linux", "windows"))
        cl = v._get("check", [], False)
        if not isinstance(cl, list):
            raise ConfigError(f"{where}.check: expected an array of tables ([[vm.check]])")
        checks = tuple(
            parse_check(
                c, f"{where}.check[{j}]", config_dir=base, default_timeout=run.default_check_timeout_s, source="config"
            )
            for j, c in enumerate(cl)
        )
        mode = v.str("mode", run.default_mode, choices=MODES)
        if mode == "manual" and not checks:
            raise ConfigError(f'{where}: mode = "manual" needs at least one [[vm.check]]')
        vms.append(
            VmTarget(
                vmid=vmid,
                temp_vmid=restore.temp_vmid_base + vmid,
                mode=mode,
                os=OsFamily(os_name) if os_name else None,
                checks=checks,
                boot_timeout_s=v.int("boot_timeout_s", run.boot_timeout_s, lo=10),
                name_hint=v.str("name", ""),
            )
        )
        v.finish()
    if run.selection == "listed" and not vms:
        raise ConfigError('no [[vm]] entries; add some or set run.selection = "all"')
    for x in run.exclude:
        _check_source_vmid(x, restore.temp_vmid_base, "run.exclude")
    root.finish()

    return Config(
        path=path,
        config_dir=base,
        target=target,
        restore=restore,
        sanitize=sanitize,
        run=run,
        node_shell=node_shell,
        screenshot=shot,
        notify=notify,
        vms=tuple(vms),
        global_checks=global_checks,
    )


def _parse_notify(n: _Section, base: Path) -> NotifyConfig:
    e = n.table("email")
    email = EmailConfig(
        enabled=e.bool("enabled", False),
        when=_when(e, NotifyWhen.FAILURE),
        per_vm=e.bool("per_vm", False),
        smtp_host=e.str("smtp_host", ""),
        smtp_port=e.int("smtp_port", 587, lo=1, hi=65535),
        security=e.str("security", "starttls", choices=("starttls", "ssl", "none")),
        username=e.str("username", ""),
        password=e.secret("password", base),
        sender=e.str("from", ""),
        to=e.str_list("to"),
        subject_prefix=e.str("subject_prefix", "[pbv]"),
        attach_screenshots=e.bool("attach_screenshots", True),
        timeout_s=e.int("timeout_s", 30, lo=1),
    )
    if email.enabled:
        if not email.smtp_host or not email.sender or not email.to:
            raise ConfigError("notify.email: smtp_host, from and to are required when enabled")
        if email.username and not email.password:
            raise ConfigError("notify.email: username set but no password_file/password_env")
    e.finish()

    t = n.table("ntfy")
    ntfy = NtfyConfig(
        enabled=t.bool("enabled", False),
        when=_when(t, NotifyWhen.FAILURE),
        per_vm=t.bool("per_vm", False),
        server=t.str("server", "https://ntfy.sh").rstrip("/"),
        topic=t.str("topic", ""),
        token=t.secret("token", base),
        priority_ok=t.str("priority_ok", "default", choices=("min", "low", "default", "high", "urgent")),
        priority_fail=t.str("priority_fail", "high", choices=("min", "low", "default", "high", "urgent")),
        tags_ok=t.str_list("tags_ok", ("white_check_mark",)),
        tags_fail=t.str_list("tags_fail", ("rotating_light",)),
        click_url=t.str("click_url", ""),
        attach_screenshots=t.bool("attach_screenshots", False),
        timeout_s=t.int("timeout_s", 15, lo=1),
    )
    if ntfy.enabled:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ntfy.topic):
            raise ConfigError("notify.ntfy.topic: required; letters, digits, _ and - (max 64)")
        if not ntfy.server.startswith(("https://", "http://")):
            raise ConfigError("notify.ntfy.server: must be an http(s) URL")
    t.finish()

    j = n.table("json")
    js = JsonConfig(
        enabled=j.bool("enabled", True),
        when=_when(j, NotifyWhen.ALWAYS),
        dir=_resolve(base, j.str("dir", "/var/lib/pbv/reports")),
        write_latest=j.bool("write_latest", True),
        stdout=j.bool("stdout", False),
        keep=j.int("keep", 90, lo=0),
    )
    j.finish()

    g = n.table("telegram")
    tg = TelegramConfig(
        enabled=g.bool("enabled", False),
        when=_when(g, NotifyWhen.FAILURE),
        per_vm=g.bool("per_vm", False),
        token=g.secret("token", base),
        chat_id=g.str("chat_id", ""),
        thread_id=g.str("thread_id", ""),
        timeout_s=g.int("timeout_s", 15, lo=1),
    )
    if tg.enabled and (not tg.token or not tg.chat_id):
        raise ConfigError("notify.telegram: token_file/token_env and chat_id are required when enabled")
    g.finish()
    n.finish()
    return NotifyConfig(email=email, ntfy=ntfy, json=js, telegram=tg)
