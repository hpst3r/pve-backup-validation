# Brief: `pbv.pve` — Proxmox VE REST client, guest agent, console capture

Implement SPEC §9 fully. Public API (re-export from `src/pbv/pve/__init__.py`):

```python
class PveClient:  # implements pbv.core.PveApi
    def __init__(self, host: str, node: str, token_id: str, token_secret: str, *,
                 port: int = 8006, verify_tls: bool = True, ca_file: str = "",
                 fingerprint: str = "", timeout_s: float = 30, retries: int = 3,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 task_poll_s: float = 2.0) -> None: ...
    @classmethod
    def from_config(cls, target: pbv.config.TargetConfig, **kw) -> "PveClient": ...
    # plus every PveApi method in core.py, plus:
    def node_names(self) -> list[str]: ...           # GET /nodes
    def cluster_name(self) -> str | None: ...       # from cluster_status
    def task_log(self, upid: str, limit: int = 20) -> list[str]: ...

class PveGuestAgent:  # implements pbv.core.GuestAgent
    def __init__(self, api: PveApi, vmid: int, *, sleep=time.sleep, clock=time.monotonic, poll_s: float = 1.0): ...

class ConsoleCapture:  # implements pbv.core.ConsoleCapturer
    def __init__(self, api: PveApi, *, mode: str, remote_dir: str, ssh_host: str = "", ssh_user: str = "root",
                 ssh_port: int = 22, ssh_key_file: str = "", ssh_known_hosts_file: str = "",
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None: ...
    @classmethod
    def from_config(cls, api, shot: pbv.config.ScreenshotConfig, **kw) -> "ConsoleCapture | None": ...  # None when mode == "off"
```

REST endpoints (PVE 8/9, prefix `/api2/json`, data under `"data"`):
- `GET /version`, `GET /nodes`, `GET /cluster/status`, `GET /nodes/{node}/network`,
  `GET /nodes/{node}/storage` (fields: storage, type, content, avail, total, active, enabled),
  `GET /nodes/{node}/storage/{storage}/content?content=backup` → items with volid, vmid, ctime, size,
  format, notes, verification ({"state": "ok"|"failed"}), encrypted (fingerprint string or absent).
  Map to `BackupRef(verified = state=="ok" if verification else None, encrypted = bool(enc) if key present else None)`.
  Filter to entries whose `content == "backup"` and whose format is a VM backup
  (`pbs-vm` or `vma.*`) — skip LXC (`pbs-ct`, `tar.*`). vmid may be int or str.
- `GET /nodes/{node}/qemu` (list_vms: vmid as int), `GET /nodes/{node}/qemu/{vmid}/config`
  (values to str; vm_exists = config GET succeeds; a 500 "does not exist" → False, other errors propagate).
- Restore: `POST /nodes/{node}/qemu` with vmid, archive, storage, unique=1, [pool], [bwlimit] → UPID.
- `PUT /nodes/{node}/qemu/{vmid}/config` with set keys + `delete=k1,k2` (comma-separated). Use PUT (synchronous).
- `GET .../status/current` → `status` field. `POST .../status/start|stop` (stop: `skiplock=1` when asked).
- `DELETE /nodes/{node}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=1[&skiplock=1]` → UPID.
- Tasks: `GET /nodes/{node}/tasks/{upid}/status`, `GET .../tasks/{upid}/log?limit=N&start=…` (lines as `{"n":..,"t":..}`),
  `DELETE /nodes/{node}/tasks/{upid}` (stop_task). UPIDs contain `:` — quote path segments (`safe=""`).
- Agent: `POST .../agent/ping`, `POST .../agent/exec` (form: `command` repeated per argv element, `input-data`),
  `GET .../agent/exec-status?pid=N` (data: exited, exitcode, out-data, err-data, out-truncated, err-truncated, signal),
  `POST .../agent/file-write` (form: file, content, encode). PVE's `encode` defaults to 1, meaning PVE
  base64-encodes the raw text you send; that is unsafe for binary/non-UTF-8 scripts. Always base64-encode the bytes
  ourselves and send `encode=0`. `GET .../agent/network-get-interfaces` (data.result list),
  `GET .../agent/get-osinfo` (data.result dict). Agent responses wrap the payload in `{"data": {"result": ...}}`
  for ping/osinfo/interfaces; exec returns `{"data": {"pid": N}}`; exec-status returns fields directly in data.
- Monitor: `POST .../monitor` (form `command`) → data is the HMP output text.

Notes and edge cases you must handle and test:
- agent_ping: PVE returns HTTP 500 with messages like "QEMU guest agent is not running" or
  "VM {vmid} is not running" or "No QEMU guest agent configured" → return False (not raise). Other errors raise.
- Transient vs final errors exactly as SPEC §9; the retry loop uses the injected sleep (backoff 1,2,4 × jitter in [0.5,1.0]).
- POST/PUT/DELETE are never retried once bytes were sent. Distinguish "connection refused" (safe to retry) from
  reset-after-send (not safe). Document how you detect it.
- wait_task polls with `task_poll_s` via injected sleep/clock; on timeout raise PbvTimeoutError(code="TASK_TIMEOUT")
  carrying the upid in the message.
- TLS pinning: build an SSLContext with CERT_NONE + check_hostname False, then after connect compare
  `sha256(sock.getpeercert(binary_form=True))` to the pin BEFORE sending the request (use http.client.HTTPSConnection
  subclass or connect manually). Mismatch → ApiError(code="TLS_PIN_MISMATCH", transient=False).
  Without a pin: default context (or cafile), verify hostname.
- `repr(PveClient)` and every exception text must not contain the token secret (test with a sentinel secret).
- PveGuestAgent.exec: exec → poll exec-status with poll_s until exited or timeout; ApiError from the agent → GuestAgentError
  (message includes PVE's message); returns ExecResult with decoded stdout/stderr, truncated flag if either truncated.
  If PVE returns out-data already decoded (it normally does), use as-is; only base64-decode when the value is valid
  base64 AND decodes to valid UTF-8 AND the original contains no whitespace other than padding — document the heuristic; prefer
  a constructor flag `b64_output: bool | None = None` (None = heuristic).
- ip_addresses: skip `lo`, 127.0.0.0/8, ::1, 169.254/16, fe80::/10; IPv4 first, preserve order, dedupe.
- ConsoleCapture: uses `api.monitor(vmid, f"screendump {remote}/{name}.png -f png")`; mode local → shutil.move
  to dest.png (create parent), mode ssh → `scp` then `ssh rm -f` via injected `run`; validate PNG magic; PPM fallback
  + converter (`pnmtopng` or `convert`, found with shutil.which) ; never raises; returns path or None; logs reason at WARNING.
  Remote filename `pbv-<vmid>-<unix ts>`. Remote dir must be created? — no: assume it exists on the node (document;
  local mode creates it with mkdir -p since it's the same host).

Tests (put in `tests/pve/`): A14 in full, using a threaded `http.server.ThreadingHTTPServer` on 127.0.0.1:0 with a
route table that records requests (method, path, headers, parsed form/query). For TLS tests generate a self-signed cert
with `openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 -days 1`
in a session fixture (skip if openssl missing); test pin match, pin mismatch, verify with ca_file, and failure without it.
Plain-HTTP is NOT a supported mode of PveClient — for non-TLS-specific tests use the TLS server with the pin
(or add an internal `_scheme="http"` test hook, clearly private). Also test PveGuestAgent and ConsoleCapture against
`pbv.testing.fakes.FakePve` (plus a fake `run`).

Acceptance ids to cover: A14 (all bullets).
