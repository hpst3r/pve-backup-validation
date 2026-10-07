"""HTTPS client for the Proxmox VE REST API (``/api2/json``), one target node.

Transport model
---------------
Every request opens a fresh :class:`http.client.HTTPSConnection` and runs in
two phases so that retries never duplicate a mutating request:

1. ``connect()`` — TCP connect, TLS handshake and (when pinned) the leaf
   certificate fingerprint check. Nothing of the HTTP request has been written
   yet, so a failure here (connection refused, connect timeout, handshake
   error) is safe to retry for *any* method.
2. ``request()`` + ``getresponse()`` — once we start writing the request we
   assume PVE may have received it. A reset, timeout or premature close in
   this phase is transient but is only retried for ``GET``; ``POST``/``PUT``/
   ``DELETE`` are never retried after this point (no double restore/start).

HTTP 502/503/504 and 500 whose message contains ``got timeout`` are transient
(retried for GET only, because the server did receive the request). Backoff is
``1, 2, 4, ... s × jitter`` with jitter uniform in ``[0.5, 1.0]``.

The API token secret is held in a :class:`_Secret` wrapper, is only ever
placed in the ``Authorization`` header, and is scrubbed from every exception
message as a second line of defence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import logging
import random
import re
import socket
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import quote, urlencode

from pbv.config import TargetConfig
from pbv.core import ApiError, BackupRef, ExecStatus, GuestAgentError, PbvTimeoutError, TaskResult

log = logging.getLogger("pbv.pve")

API_PREFIX = "/api2/json"
FILE_WRITE_MAX_ENCODED = 60 * 1024
"""PVE's ``maxLength`` for the ``content`` parameter of ``agent/file-write``.

The limit applies to the base64 text we send (``encode=0``), so the largest
raw file is ``FILE_WRITE_MAX_ENCODED * 3 // 4`` = 46080 bytes."""
FILE_WRITE_MAX_BYTES = FILE_WRITE_MAX_ENCODED * 3 // 4

_TRANSIENT_STATUS = frozenset({502, 503, 504})
_AGENT_DOWN = re.compile(
    r"guest agent is not running|no qemu guest agent configured|vm \d+ is not running|got timeout",
    re.IGNORECASE,
)
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

Params = Mapping[str, Any]


class _Secret:
    """Holds a secret string; its ``repr``/``str`` never reveal the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<redacted>"

    __str__ = __repr__


class _Attempt(Exception):
    """One failed request attempt (internal): the error and whether bytes were sent."""

    def __init__(self, error: ApiError, *, sent: bool) -> None:
        super().__init__(str(error))
        self.error = error
        self.sent = sent


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that checks the leaf certificate's SHA-256 right after the handshake.

    The check runs inside :meth:`connect`, i.e. before any request byte is
    written, so a mismatching server never sees the Authorization header.
    """

    def __init__(self, host: str, port: int, *, timeout: float, context: ssl.SSLContext, pin: str) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pin = pin

    def connect(self) -> None:
        super().connect()
        if not self._pin:
            return
        der = self.sock.getpeercert(binary_form=True) if self.sock is not None else None
        actual = hashlib.sha256(der or b"").hexdigest()
        if actual != self._pin:
            self.close()
            raise ApiError(
                f"TLS certificate fingerprint mismatch for {self.host}:{self.port}: "
                f"expected sha256 {_fmt_fp(self._pin)}, got {_fmt_fp(actual)}",
                code="TLS_PIN_MISMATCH",
                transient=False,
            )


def _fmt_fp(hexdigest: str) -> str:
    return ":".join(hexdigest[i : i + 2] for i in range(0, len(hexdigest), 2)).upper()


def normalize_fingerprint(fp: str) -> str:
    """``"AA:BB:.."`` / ``"aabb.."`` → lowercase hex without separators."""
    return fp.replace(":", "").replace(" ", "").strip().lower()


def api_path(*segments: object) -> str:
    """Join path segments, URL-quoting each one completely (``/`` and ``:`` included)."""
    return "".join("/" + quote(str(s), safe="") for s in segments)


def _encode_params(params: Params | None) -> str:
    """Form/query encoding: drop ``None``, booleans → ``1``/``0``, sequences repeat the key."""
    pairs: list[tuple[str, str]] = []
    for key, value in (params or {}).items():
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            if v is None:
                continue
            if isinstance(v, bool):
                v = int(v)
            pairs.append((key, str(v)))
    return urlencode(pairs)


def _maybe_b64(value: str, flag: bool | None) -> str:
    """Decode agent output that might be base64.

    ``flag`` True: always try to decode (invalid → raw text); False: never.
    ``None`` (heuristic): PVE normally returns decoded text, so only decode
    when the value consists solely of base64 alphabet characters (no
    whitespace at all, padding only at the end), has a length that is a
    multiple of 4, *and* decodes to valid UTF-8. Real command output almost
    always ends in a newline, which keeps it out of this path.
    """
    if not value or flag is False:
        return value
    if flag is None and (len(value) % 4 or not _B64.match(value)):
        return value
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return value


def _as_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class PveClient:
    """Implements :class:`pbv.core.PveApi` over HTTPS with an API token.

    TLS modes: with ``fingerprint`` the chain is not verified but the leaf
    certificate's SHA-256 must equal the pin (``TLS_PIN_MISMATCH`` otherwise);
    without it the system CA store (or ``ca_file``) and hostname are verified;
    ``verify_tls=False`` without a pin disables verification and logs one
    warning.
    """

    def __init__(
        self,
        host: str,
        node: str,
        token_id: str,
        token_secret: str,
        *,
        port: int = 8006,
        verify_tls: bool = True,
        ca_file: str = "",
        fingerprint: str = "",
        timeout_s: float = 30,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        task_poll_s: float = 2.0,
        b64_output: bool | None = None,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self.host = host
        self.node = node
        self.port = port
        self.token_id = token_id
        self._secret = _Secret(token_secret)
        self._pin = normalize_fingerprint(fingerprint)
        self._timeout_s = timeout_s
        self._retries = max(0, retries)
        self._sleep = sleep
        self._clock = clock
        self._task_poll_s = task_poll_s
        self._b64_output = b64_output
        self._jitter = jitter or (lambda: random.uniform(0.5, 1.0))  # noqa: S311 - backoff jitter, not crypto
        self._ssl = self._make_context(verify_tls, ca_file)

    # ── construction ───────────────────────────────────────────────────────────
    @classmethod
    def from_config(cls, target: TargetConfig, **kw: Any) -> PveClient:
        """Build a client from ``[target]``; ``kw`` overrides (e.g. ``sleep``) for tests."""
        args: dict[str, Any] = {
            "port": target.port,
            "verify_tls": target.verify_tls,
            "ca_file": target.ca_file,
            "fingerprint": target.fingerprint,
            "timeout_s": target.api_timeout_s,
            "retries": target.api_retries,
        }
        args.update(kw)
        return cls(target.host, target.node, target.token_id, target.token_secret, **args)

    def _make_context(self, verify_tls: bool, ca_file: str) -> ssl.SSLContext:
        if self._pin or not verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if not self._pin:
                log.warning(
                    "TLS_VERIFY_DISABLED host=%s (no certificate pin; connection is not authenticated)", self.host
                )
            return ctx
        return ssl.create_default_context(cafile=ca_file or None)

    def __repr__(self) -> str:
        return f"PveClient(host={self.host!r}, port={self.port}, node={self.node!r}, token_id={self.token_id!r})"

    # ── transport ──────────────────────────────────────────────────────────────
    def _scrub(self, text: str) -> str:
        secret = self._secret.get()
        return text.replace(secret, "<redacted>") if secret else text

    def _error(self, message: str, **kw: Any) -> ApiError:
        return ApiError(self._scrub(message), **kw)

    def _connection(self) -> http.client.HTTPSConnection:
        return _PinnedHTTPSConnection(self.host, self.port, timeout=self._timeout_s, context=self._ssl, pin=self._pin)

    def request(self, method: str, path: str, params: Params | None = None) -> dict[str, Any]:
        """Perform one API call with retries; returns the decoded JSON body (``{"data": ...}``)."""
        attempt = 0
        while True:
            try:
                return self._once(method, path, params)
            except _Attempt as failed:
                err = failed.error
                retryable = err.transient and (method == "GET" or not failed.sent)
                if not retryable or attempt >= self._retries:
                    raise err from None
                delay = (2**attempt) * self._jitter()
                log.warning(
                    "API_RETRY method=%s path=%s attempt=%d delay=%.1fs reason=%s",
                    method,
                    path,
                    attempt + 1,
                    delay,
                    err,
                )
                self._sleep(delay)
                attempt += 1

    def _once(self, method: str, path: str, params: Params | None) -> dict[str, Any]:
        url = API_PREFIX + path
        encoded = _encode_params(params)
        body: bytes | None = None
        headers = {
            "Authorization": f"PVEAPIToken={self.token_id}={self._secret.get()}",
            "Accept": "application/json",
        }
        if method in ("POST", "PUT"):
            body = encoded.encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif encoded:
            url += "?" + encoded
        where = f"{method} {path}"
        conn = self._connection()
        try:
            # Phase 1: connect (+TLS, +pin). Nothing sent yet → retry-safe for any method.
            try:
                conn.connect()
            except ApiError as e:  # pin mismatch
                raise _Attempt(e, sent=False) from None
            except ssl.SSLCertVerificationError as e:
                raise _Attempt(
                    self._error(
                        f"{where}: TLS certificate verification failed: {e.verify_message}", code="TLS_VERIFY_FAIL"
                    ),
                    sent=False,
                ) from None
            except socket.gaierror as e:
                transient = e.errno == socket.EAI_AGAIN
                raise _Attempt(
                    self._error(
                        f"{where}: cannot resolve {self.host}: {e}", transient=transient, code="API_UNREACHABLE"
                    ),
                    sent=False,
                ) from None
            except (OSError, http.client.HTTPException) as e:
                raise _Attempt(
                    self._error(
                        f"{where}: cannot connect to {self.host}:{self.port}: {e}",
                        transient=True,
                        code="API_UNREACHABLE",
                    ),
                    sent=False,
                ) from None
            # Phase 2: request written → the server may have acted on it.
            log.debug("API_REQUEST method=%s path=%s", method, path)
            try:
                conn.request(method, url, body=body, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
            except (OSError, http.client.HTTPException) as e:
                raise _Attempt(
                    self._error(
                        f"{where}: connection failed after sending request: {type(e).__name__}: {e}", transient=True
                    ),
                    sent=True,
                ) from None
        finally:
            conn.close()
        return self._decode(where, resp.status, resp.reason, raw)

    def _decode(self, where: str, status: int, reason: str, raw: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, ValueError):
            payload = None
        if 200 <= status < 300:
            if not isinstance(payload, dict):
                raise _Attempt(
                    self._error(
                        f"{where}: HTTP {status}: response is not a JSON object", status=status, code="API_BAD_RESPONSE"
                    ),
                    sent=True,
                )
            return payload
        message = ""
        errors: Any = None
        if isinstance(payload, dict):
            message = str(payload.get("message") or "").strip()
            errors = payload.get("errors")
        if not message:
            message = (reason or "").strip()
        if isinstance(errors, dict) and errors:
            details = "; ".join(f"{k}: {str(v).strip()}" for k, v in sorted(errors.items()))
            message = f"{message} ({details})" if message else details
        transient = status in _TRANSIENT_STATUS or (status == 500 and "got timeout" in message.lower())
        hint = ""
        if status == 401:
            hint = " (authentication failed: check target.token_id / token secret)"
        elif status == 403:
            hint = " (permission denied for this API token)"
        raise _Attempt(
            self._error(
                f"{where}: HTTP {status}: {message or 'no error message'}{hint}", status=status, transient=transient
            ),
            sent=True,
        )

    def _get(self, path: str, params: Params | None = None) -> Any:
        return self.request("GET", path, params).get("data")

    def _post(self, path: str, params: Params | None = None) -> Any:
        return self.request("POST", path, params).get("data")

    def _node(self, *segments: object) -> str:
        return api_path("nodes", self.node, *segments)

    def _qemu(self, vmid: int, *segments: object) -> str:
        return self._node("qemu", int(vmid), *segments)

    def _upid(self, data: Any, where: str) -> str:
        if not isinstance(data, str) or not data:
            raise self._error(f"{where}: expected a task UPID, got {type(data).__name__}", code="API_BAD_RESPONSE")
        return data

    # ── cluster / node / storage ───────────────────────────────────────────────
    def version(self) -> dict[str, Any]:
        return dict(self._get("/version") or {})

    def node_names(self) -> list[str]:
        """Names of all nodes known to the API (``GET /nodes``)."""
        return [str(n["node"]) for n in self._get("/nodes") or [] if "node" in n]

    def cluster_status(self) -> list[dict[str, Any]]:
        return [dict(x) for x in self._get("/cluster/status") or []]

    def cluster_name(self) -> str | None:
        """The cluster name, or None on a standalone node."""
        for entry in self.cluster_status():
            if entry.get("type") == "cluster":
                return str(entry.get("name", "")) or None
        return None

    def node_networks(self) -> list[dict[str, Any]]:
        return [dict(x) for x in self._get(self._node("network")) or []]

    def storage_list(self) -> list[dict[str, Any]]:
        return [dict(x) for x in self._get(self._node("storage")) or []]

    def list_backups(self, storage: str) -> list[BackupRef]:
        """VM backups on ``storage`` (LXC and non-backup content are skipped)."""
        items = self._get(self._node("storage", storage, "content"), {"content": "backup"}) or []
        out: list[BackupRef] = []
        for it in items:
            fmt = str(it.get("format", ""))
            if it.get("content", "backup") != "backup" or not (fmt == "pbs-vm" or fmt.startswith("vma")):
                continue
            vmid = _as_int(it.get("vmid"))
            if vmid is None or not it.get("volid"):
                continue
            verification = it.get("verification")
            verified = verification.get("state") == "ok" if isinstance(verification, dict) else None
            out.append(
                BackupRef(
                    volid=str(it["volid"]),
                    vmid=vmid,
                    ctime=_as_int(it.get("ctime"), 0) or 0,
                    size=_as_int(it.get("size"), 0) or 0,
                    format=fmt,
                    notes=str(it.get("notes") or ""),
                    verified=verified,
                    encrypted=bool(it["encrypted"]) if "encrypted" in it else None,
                )
            )
        return out

    # ── VMs ────────────────────────────────────────────────────────────────────
    def list_vms(self) -> list[dict[str, Any]]:
        out = []
        for vm in self._get(self._node("qemu")) or []:
            vmid = _as_int(vm.get("vmid"))
            if vmid is None:
                continue
            out.append(
                {
                    **vm,
                    "vmid": vmid,
                    "name": str(vm.get("name") or ""),
                    "status": str(vm.get("status") or ""),
                    "tags": str(vm.get("tags") or ""),
                }
            )
        return out

    def get_vm_config(self, vmid: int) -> dict[str, str]:
        data = self._get(self._qemu(vmid, "config")) or {}
        return {str(k): str(v) for k, v in data.items()}

    def vm_exists(self, vmid: int) -> bool:
        try:
            self._get(self._qemu(vmid, "config"))
        except ApiError as e:
            if e.status == 500 and "does not exist" in str(e):
                return False
            raise
        return True

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
        params = {
            "vmid": int(vmid),
            "archive": archive,
            "storage": storage,
            "unique": unique,
            "pool": pool or None,
            "bwlimit": bwlimit_kib if bwlimit_kib else None,
        }
        return self._upid(self._post(self._node("qemu"), params), "restore")

    def update_vm_config(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str] = ()) -> None:
        params: dict[str, Any] = dict(set_)
        if delete:
            params["delete"] = ",".join(delete)
        if params:
            self.request("PUT", self._qemu(vmid, "config"), params)

    def vm_status(self, vmid: int) -> str:
        return str((self._get(self._qemu(vmid, "status", "current")) or {}).get("status", ""))

    def start_vm(self, vmid: int) -> str:
        return self._upid(self._post(self._qemu(vmid, "status", "start")), "start")

    def stop_vm(self, vmid: int, *, skiplock: bool = False) -> str:
        return self._upid(self._post(self._qemu(vmid, "status", "stop"), {"skiplock": skiplock or None}), "stop")

    def destroy_vm(self, vmid: int, *, skiplock: bool = False) -> str:
        params = {"purge": 1, "destroy-unreferenced-disks": 1, "skiplock": skiplock or None}
        return self._upid(self.request("DELETE", self._qemu(vmid), params).get("data"), "destroy")

    # ── tasks ──────────────────────────────────────────────────────────────────
    def stop_task(self, upid: str) -> None:
        self.request("DELETE", self._node("tasks", upid))

    def task_log(self, upid: str, limit: int = 20) -> list[str]:
        """The last ``limit`` lines of a task log."""
        path = self._node("tasks", upid, "log")
        head = self.request("GET", path, {"start": 0, "limit": 1})
        total = _as_int(head.get("total"))
        if total is None:  # older/odd servers: fetch generously and slice
            lines = self.request("GET", path, {"start": 0, "limit": 100000}).get("data") or []
        else:
            lines = self._get(path, {"start": max(0, total - limit), "limit": limit}) or []
        text = [str(ln.get("t", "")) if isinstance(ln, dict) else str(ln) for ln in lines]
        return text[-limit:] if limit > 0 else []

    def wait_task(self, upid: str, timeout_s: float) -> TaskResult:
        """Poll a task until it stops; ``ok`` iff exitstatus is ``OK`` (or ``WARNINGS: n``)."""
        deadline = self._clock() + timeout_s
        path = self._node("tasks", upid, "status")
        while True:
            data = self._get(path) or {}
            if data.get("status") == "stopped":
                exitstatus = str(data.get("exitstatus", ""))
                ok = exitstatus == "OK" or exitstatus.startswith("WARNINGS")
                tail: tuple[str, ...] = ()
                if exitstatus != "OK":
                    try:
                        tail = tuple(self.task_log(upid, 20))
                    except ApiError as e:
                        tail = (f"(task log unavailable: {e})",)
                return TaskResult(upid=upid, exitstatus=exitstatus, ok=ok, log_tail=tail)
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise PbvTimeoutError(f"task {upid} did not finish within {timeout_s:g}s", code="TASK_TIMEOUT")
            self._sleep(min(self._task_poll_s, remaining))

    # ── guest agent / monitor ──────────────────────────────────────────────────
    def agent_ping(self, vmid: int) -> bool:
        try:
            self._post(self._qemu(vmid, "agent", "ping"))
        except ApiError as e:
            if e.status == 500 and _AGENT_DOWN.search(str(e)):
                return False
            raise
        return True

    def agent_exec(self, vmid: int, argv: Sequence[str], input_data: bytes | None = None) -> int:
        if not argv:
            raise GuestAgentError("agent exec: empty command")
        params: dict[str, Any] = {"command": list(argv)}
        if input_data is not None:
            try:
                params["input-data"] = bytes(input_data).decode("utf-8")
            except UnicodeDecodeError:
                raise GuestAgentError("agent exec: input-data must be valid UTF-8") from None
        data = self._post(self._qemu(vmid, "agent", "exec"), params) or {}
        pid = _as_int(data.get("pid")) if isinstance(data, dict) else None
        if pid is None:
            raise self._error(f"agent exec on VM {vmid}: no pid in response", code="API_BAD_RESPONSE")
        return pid

    def agent_exec_status(self, vmid: int, pid: int) -> ExecStatus:
        d = self._get(self._qemu(vmid, "agent", "exec-status"), {"pid": int(pid)}) or {}
        return ExecStatus(
            exited=bool(d.get("exited")),
            exitcode=_as_int(d.get("exitcode")),
            stdout=_maybe_b64(str(d.get("out-data") or ""), self._b64_output),
            stderr=_maybe_b64(str(d.get("err-data") or ""), self._b64_output),
            out_truncated=bool(d.get("out-truncated")),
            err_truncated=bool(d.get("err-truncated")),
            signal=_as_int(d.get("signal")),
        )

    def agent_file_write(self, vmid: int, path: str, content: bytes) -> None:
        encoded = base64.b64encode(bytes(content)).decode("ascii")
        if len(encoded) > FILE_WRITE_MAX_ENCODED:
            raise GuestAgentError(
                f"agent file-write {path}: {len(content)} bytes exceeds the PVE limit of {FILE_WRITE_MAX_BYTES} bytes"
            )
        self._post(self._qemu(vmid, "agent", "file-write"), {"file": path, "content": encoded, "encode": 0})

    def agent_network_interfaces(self, vmid: int) -> list[dict[str, Any]]:
        data = self._get(self._qemu(vmid, "agent", "network-get-interfaces")) or {}
        result = data.get("result") if isinstance(data, dict) else None
        return [dict(x) for x in result or [] if isinstance(x, dict)]

    def agent_osinfo(self, vmid: int) -> dict[str, Any]:
        data = self._get(self._qemu(vmid, "agent", "get-osinfo")) or {}
        result = data.get("result") if isinstance(data, dict) else None
        return dict(result) if isinstance(result, dict) else {}

    def monitor(self, vmid: int, command: str) -> str:
        data = self._post(self._qemu(vmid, "monitor"), {"command": command})
        return "" if data is None else str(data)
