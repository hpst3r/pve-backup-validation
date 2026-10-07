# pbv — Proxmox Backup Validation (SPEC, authoritative)

A Python rewrite of `legacy/backup_validation.sh` (Tobidp/pve-backup-validation).
It restores the newest PBS backup of each configured VM onto a **separate,
standalone restore node** (never the production cluster). Each restored VM is
booted on an isolated bridge and validated with built-in checks and **arbitrary
scripts**. Results go out by email, ntfy, a JSON report and (optionally)
Telegram, and every temporary VM is destroyed.

Python ≥ 3.11, **stdlib only at runtime**: `urllib`/`http.client`, `ssl`,
`smtplib`, `email`, `tomllib`, `subprocess`, `logging`, `fcntl`. Dev only:
`pytest`, `ruff`. The runner can be the restore node itself or any Linux host
that can reach the restore node's API on port 8006.

## 1. Topology and safety model

```
 production cluster ──backup──▶  PBS  ◀──read (PBS storage)── restore node (standalone PVE)
                                                                │  vmbr-pbv: isolated bridge (no ports, no IP)
 runner (pbv) ──HTTPS API token──────────────────────────────────┘  temp VMs 900000+<vmid>
```

- pbv talks ONLY to the restore node's REST API (`/api2/json`) with an API
  token. It never touches the production cluster. The restore node has the
  production PBS datastore added as a storage (preferably a PBS user limited
  to `DatastoreReader`, plus the encryption key if the backups are encrypted).
- **Preflight guards (all must pass before anything is created):**
  1. `target.node` exists in `GET /nodes` and is the node the API is serving.
  2. If `target.require_standalone` (default true), `GET /cluster/status`
     must contain no entry with `type == "cluster"`. If the node is clustered
     anyway (require_standalone = false), its cluster name must not be in
     `target.forbid_cluster_names`. Either violation → `PREFLIGHT_FAIL`.
  3. `restore.isolated_bridge` exists on the node and has `type == "bridge"`.
     If `require_isolated_bridge` (default true), it must have no bridge ports
     (`bridge_ports` empty or `"none"`), no `cidr`/`address`/`cidr6`/`address6`
     and no `gateway`. This means the bridge cannot route anywhere.
  4. `restore.backup_storage` exists, has `type == "pbs"`, and is active and
     enabled.
  5. `restore.target_storage` exists, is active and enabled, and its
     `content` includes `images`.
  6. The temp VMID range `[temp_vmid_base+100, 2*temp_vmid_base)` is used by
     no VM that lacks the pbv tag. Untagged VMs in the range → `PREFLIGHT_FAIL`,
     because cleanup would never be allowed to remove them.
- **Temp VMID** = `restore.temp_vmid_base + source_vmid` (default base
  900000, so 105 → 900105). Source VMIDs must be `100 ≤ vmid < base`.
- **Destroy guard** (`may_destroy(vmid)`): the VMID is in the temp range AND
  (its config `tags` contains `restore.tag` OR this run itself issued the
  restore for that VMID). Anything else raises `SafetyError` and is reported
  as critical. The guard is checked immediately before every stop and destroy.
- Restored VMs are tagged, described, and get `onboot=0` and
  `protection` removed in the very first config update after restore.

### 1a. root-only operations (contract amendment, decided after wave 1 launch)

Verified against the qemu-server source (master, `src/PVE/API2/Qemu.pm`,
`HMPPerms.pm`). For anyone other than `root@pam`, and an API token is never
`root@pam`:
- Changing or deleting `hostpci*` with `host=` (non-mapped) dies with "only
  root can set … for non-mapped devices". `usb*` is the same for non-mapped
  devices. Changing `serial*` to or from a real device is root-only. `args`
  and `hookscript` are root-only.
- HMP `screendump` has permission `root` ("dump to arbitrary target file"),
  so the API monitor call fails for tokens on PVE 9.

These operations therefore go through a `pbv.core.NodeShell`
(`[node_shell] mode = off|local|ssh`). In `local` mode pbv runs `qm` as root
on the restore node itself; in `ssh` mode it uses
`ssh -o BatchMode=yes -o StrictHostKeyChecking=yes root@node`.
- Sanitize splits its plan into `api` keys (everything else) and `root` keys
  (matching `pbv.testing.fakes.PRIVILEGED_KEY`, except `serial*` values that
  are `socket` both before and after). The api part is one `update_vm_config`;
  the root part is one `NodeShell.qm_set`. If there are root keys and
  node_shell is off → `SANITIZE_NEEDS_ROOT` (FAIL), with the message listing
  the keys and pointing at `[node_shell]`.
- Screenshots use `NodeShell.screendump` (which runs `qm monitor <vmid>` with
  `screendump <remote_dir>/x.png -f png`, then copies the file back with scp
  in ssh mode, or moves it in local mode). `[screenshot] enabled` requires
  node_shell. `ScreenshotConfig` is now only `enabled` + `when`, and the
  ssh/remote_dir fields moved to `NodeShellConfig`.
- `qm set` is run as `qm set <vmid> --<k> <v> ... --delete k1,k2`, every
  argument shlex-quoted for the remote shell. A non-zero exit →
  `PbvError(code="NODE_SHELL_FAIL")` with the last stderr line (≤ 200 chars).
- `pbv.pve.NodeShellRunner(cfg: NodeShellConfig, *, run=subprocess.run, which=shutil.which)`
  implements NodeShell plus `probe() -> str` (raises `PbvError(code="NODE_SHELL_FAIL")`), used by preflight.
  `ConsoleCapture(shell: NodeShell)` adapts it to `ConsoleCapturer`; `ConsoleCapture.from_config(shell, shot)`
  returns None unless `shot.enabled`.
- `Runner(..., node_shell: NodeShell | None = None)`; `preflight(api, cfg, node_shell=None)`.
- Preflight adds a `node_shell` step when mode != off: run `true` (ssh) or
  check `os.geteuid() == 0` and `shutil.which("qm")` (local).

## 2. Lifecycle per VM (sequential; one VM at a time)

Each step yields a `StepResult` (`name`, `status`, `duration_s`, `message`,
`error_code`). The first fatal step sets `VmResult.failure_code`. Steps after a
fatal step are skipped, but cleanup always runs.

| # | Step | Failure code → VM status |
|---|------|--------------------------|
| 1 | `resolve_backup`: newest `BackupRef` by `ctime` for the vmid on `backup_storage` | `NO_BACKUP` → FAIL |
| 1b | Age check, if `max_backup_age_h > 0` (non-fatal: the test continues) | `BACKUP_TOO_OLD` → FAIL |
| 2 | `temp_vmid`: if the temp VMID exists and `may_destroy` allows it, sweep it (it's a leftover); otherwise abort | `TEMP_VMID_BUSY` → ERROR |
| 3 | `space`: storage `avail ≥ backup.size × min_free_space_ratio` (skipped if size is 0 or `avail` is unknown) | `INSUFFICIENT_SPACE` → ERROR |
| 4 | `restore`: `POST /nodes/{n}/qemu` with `vmid`, `archive`, `storage`, `unique=1`, optional `pool` and `bwlimit`; then wait for the task (`restore_timeout_s`). On timeout, call `stop_task(upid)` | `RESTORE_FAIL` → FAIL (task exitstatus + log tail in message); `RESTORE_TIMEOUT` → FAIL |
| 5 | `mark`: set `tags` (existing + `restore.tag`), `description` marker, `onboot=0`; delete `protection` | `SANITIZE_FAIL` → ERROR |
| 6 | `sanitize`: see §3; a single `update_vm_config(set, delete)` call | `SANITIZE_FAIL` → ERROR (a 403 adds the hint "token lacks privilege — hostpci/usb/args/hookscript changes need root@pam") |
| 7 | `start`: start the VM and wait for the task (120 s) | `START_FAIL` → FAIL (task exitstatus) |
| 8 | `boot`: poll `agent_ping` every 5 s until `boot_timeout_s`. If `vm_status` turns `stopped`, that is `BOOT_FAIL`. Take a console screenshot when screenshots are not `off` | `BOOT_TIMEOUT` / `BOOT_FAIL` → FAIL |
| 9 | `settle`: sleep `run.settle_s`. OS = the configured `os`, else `GuestAgent.os_family()`. IPs = `GuestAgent.ip_addresses()` (an empty list is fine) | — |
| 10 | `checks`: `CheckSuite.plan(...)`, then `run` each check. VM status is the worst over check statuses | `CHECKS_FAILED` (any critical FAIL/ERROR) → FAIL/ERROR; non-critical failures → WARN |
| 11 | `screenshot`: if `screenshot.when == "always"`, or if the VM status is worse than PASS | never fatal |
| 12 | `cleanup` (always, in `finally`) — see §4 | `CLEANUP_FAIL` → ERROR, `cleanup_ok=False` |

Any unexpected exception inside a VM's lifecycle is caught. It is logged with
a traceback to the VM log, recorded as `INTERNAL_ERROR` (status ERROR),
cleanup still runs, and the run continues with the next VM. If an `ApiError`
with `status is None` (connection/TLS failure) occurs during two consecutive
VMs, the run aborts the remaining VMs with `API_UNREACHABLE` (ERROR).

`keep_on_failure = true` changes cleanup for failed VMs only: the VM is left
running, gets the extra tag `pbv-keep`, and is listed in the report. Sweeps
never destroy `pbv-keep` VMs. Manual `pbv cleanup --include-kept` does.

## 3. Sanitize rules (pure function, unit-tested exhaustively)

`sanitize_config(cfg: dict[str,str], *, bridge, storages: set[str], opts) ->
SanitizePlan(set: dict, delete: list, notes: list[str], warnings: list[str])`.
The `set` and `delete` keys never overlap. Order of `notes` is deterministic
(sorted by key).

- `net\d+`: set `bridge=<isolated_bridge>`, `firewall=0`; remove `tag=`,
  `trunks=`, `rate=` and `link_down=`. Keep the model and MAC and every other
  option.
- `hostpci\d+`, `usb\d+`, `parallel\d+`, `virtiofs\d+`: delete
  ("removed passthrough").
- `serial\d+`: keep `socket` values when `keep_serial`; delete everything else
  (host device paths).
- CD-ROM drives (`ide|sata|scsi\d+` with `media=cdrom`): if the volume is not
  `none`/`cdrom`, and is not a cloud-init volume (`vm-<id>-cloudinit`), set
  the value to `none,media=cdrom` ("ejected ISO <volid>").
- Any other disk (`ide|sata|scsi|virtio\d+`, `efidisk0`, `tpmstate0`,
  `unused\d+`) whose `storage:` prefix is not in the node's storages: delete it
  and add a warning ("disk on missing storage X removed"). Raw device paths
  (`/dev/...`) are deleted with a warning.
- Delete `hookscript`, `args`, `startup`, `affinity`, `hugepages`
  (host-specific). Set `onboot=0` (already done by mark; idempotent).
- `agent`: if it is missing, or its first/enabled field is `0`, set `agent=1`,
  preserving the other options ("enabled guest agent").
- `cpu`: if `sanitize.cpu_override` is set, set `cpu=<override>` and record
  the old value in the notes.
- `memory`: if `memory_max_mib > 0` and the VM's memory is larger, set
  `memory=<max>`. If `balloon` is larger than the new max, set `balloon` to
  the same value.
- `vga`: if `sanitize.vga` is set, set it (for example `std`, which makes
  screenshots work).

## 4. Cleanup guarantees

For a temp VM, guarded by `may_destroy`:
1. If its status is not `stopped`: `stop_vm` and wait 120 s. If PVE reports
   a lock and the VM was created by this run, retry with `skiplock=True`.
2. `destroy_vm` (purge + destroy unreferenced disks) and wait 300 s. Lock
   handling is the same as in step 1.
3. Verify: `vm_exists` is False.
4. Retry steps 1–3 up to 3 times with backoff of 5, 15 and 30 s
   (`sleep` is injectable for tests).
5. On final failure: `cleanup_ok=False`, step `cleanup` ERROR
   `CLEANUP_FAIL`, run status ERROR, exit code 3. Notifications carry the
   line `MANUAL CLEANUP REQUIRED: VM <id> on <node>`.

**Startup sweep** (`run.sweep_leftovers`, default true): before the first VM,
every VM on the node that is in the temp range, carries the pbv tag, and is
not tagged `pbv-keep` is cleaned up (after stopping a running one). The
VMIDs go in `report.leftovers_swept`.

**Signals:** SIGINT/SIGTERM set a flag. Polling loops (task wait, boot wait,
check retries, guest exec waits through the orchestrator) check the flag and
raise `InterruptedRun` at the next poll. While cleanup runs, signals are only
recorded; cleanup finishes first. A second signal during cleanup is logged and
ignored. The report is marked `interrupted`, its status is ERROR, notifiers
still run (the JSON report is always written) and the exit code is 130. The
orchestrator gets the flag through an injectable `should_stop: Callable[[],
bool]`.

**Lock:** `fcntl.flock(LOCK_EX|LOCK_NB)` on `run.lock_file`. If it is held:
message `another pbv run is in progress`, exit 4, no notifications.

## 5. Checks

`CheckEngine(config_dir: Path, global_checks: Sequence[CheckSpec], *,
host_env: Mapping[str,str] | None = None, sleep=time.sleep, clock=time.monotonic)`
implements `CheckSuite`.

**plan(target, guest, os)** returns, in order and de-duplicated by `name`
(first wins):
- `manual`: `target.checks` + global checks.
- `auto`: discovered + global checks (target.checks are ignored, with a
  warning that the orchestrator logs; the config loader already rejects
  manual without checks).
- `hybrid`: `target.checks` + discovered + global.

Discovery never raises. If listing services fails, the result is a single
discovered check of type `"_discovery_error"`, which `run` reports as WARN
with the error text.

**Discovery signatures.** Linux uses enabled systemd units from
`systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager`;
Windows uses services with `StartType -eq 'Automatic'` from PowerShell
`Get-Service | ...`. Each matched signature yields a systemd/windows_service
check plus a tcp_listen or http check (`source="discovered"`, `critical=True`,
`wait_s=60`). The Linux list is the legacy one (apache2|httpd, nginx,
postgresql|postgresql@*, mariadb|mysql|mysqld, redis-server|redis,
mongod|mongodb, clickhouse-server, docker (unit only), elasticsearch,
rabbitmq-server) plus sshd|ssh:22, and cloudflared becomes a
`log_scan(unit=cloudflared, ignore_regex=<legacy network-error regex>)`.
The Windows list is W3SVC→http 80, MSSQLSERVER→tcp 1433, NTDS→tcp 389 + tcp
88, DNS→tcp 53, TermService→tcp 3389 and LanmanServer→tcp 445.

**run(spec, guest, ctx)** never raises. It returns `CheckResult`:
- `only_os` mismatch → SKIPPED.
- Each attempt is bounded by `spec.timeout_s`. If it fails and `wait_s > 0`,
  the check retries every 3 s (configurable) until `wait_s` has elapsed;
  `attempts` is counted.
- Failure maps to FAIL when `critical`, else WARN. A `GuestAgentError` or
  agent `ApiError` → ERROR (critical) / WARN, with code `GUEST_AGENT_ERROR`
  in the summary.
- `summary` is one line ≤ 200 chars. `detail` is ≤ 8 KiB (keep the tail and
  mark truncation).
- All guest commands are argv lists. Values that go into a shell (Linux `sh
  -c` / PowerShell `-Command`) are quoted with `shlex.quote` / PowerShell
  single-quote doubling, and a test proves an injection attempt is inert.

Check types (params as validated in `pbv/config.py` `CHECK_TYPES`):
| type | Linux | Windows |
|---|---|---|
| `systemd` | `systemctl is-active <unit>` == `active`. On failure, the detail holds `systemctl show -p ActiveState,SubState,Result` + `journalctl -u <unit> -n 15` | SKIPPED (only_os) |
| `windows_service` | SKIPPED | PowerShell `(Get-Service -Name '<s>').Status` == `Running` |
| `tcp_listen` | `ss -ltnH` (fallback `netstat -ltn`) has a socket on the port | `Get-NetTCPConnection -State Listen -LocalPort <p>` (fallback `netstat -an`) |
| `http` | In the guest: curl `-sk -o /dev/null -w '%{http_code}'`, wget fallback, against `scheme://host:port/path`. If `body_regex` is set, fetch the body (≤ 64 KiB) and match it. Default accepted: 2xx/3xx/401/403, else `expect_status`. No HTTP client in the guest → fall back to tcp_listen, and the result is WARN ("no HTTP client; port listening") | `Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0`, certificate check disabled for PS 5.1 and 7 |
| `command` | Runs `argv` directly | same |
| `script` | Reads the local file (`params.path`, absolute), writes it into the guest with `write_file` to `/tmp/pbv-<run_id>-<n>-<basename>`, then runs `[interpreter or /bin/sh, path, *args]`. Env is applied with `/usr/bin/env K=V ...`. Best-effort `rm -f` afterwards | Path `C:\Windows\Temp\pbv-<run_id>-<n>-<basename>`. The interpreter is chosen by extension: `.ps1` → `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File`, `.cmd`/`.bat` → `cmd.exe /c`, otherwise powershell. Env is set through a PowerShell wrapper; best-effort delete afterwards |
| `host_script` | Runs on the **runner**: `subprocess.run([path, *args], timeout, start_new_session=True)`. On timeout the whole process group gets SIGTERM, then SIGKILL after 5 s | same |
| `log_scan` | `journalctl -u <unit> --since <since> --no-pager -o cat`, counting lines that match `error_regex` and not `ignore_regex` (Python-side). PASS if count ≤ `max_matches` | SKIPPED |

For `command` / `script` / `host_script`: an exit code in `expect_exit` →
PASS, in `warn_exit` → WARN, otherwise FAIL (WARN if non-critical). If
`stdout_regex` is set, it must also match stdout. A timeout → FAIL with
"timed out after Ns (guest process may still be running)".

**Script environment.** Every guest/host script receives `PBV_RUN_ID`,
`PBV_VMID` (source), `PBV_TEMP_VMID`, `PBV_VM_NAME`, `PBV_OS`,
`PBV_GUEST_IPS` (comma-separated), `PBV_GUEST_IP` (the first IP or empty),
`PBV_TARGET_NODE` and `PBV_CHECK_NAME`, plus the user's `env`. Host scripts
also get `PBV_WORK_DIR` (a per-VM artifact dir they may write into) and
inherit only `PATH`, `LANG`, `HOME` and the `host_env` mapping from the
runner. Secrets are never passed.

## 6. Notifications

`build_notifiers(cfg: pbv.config.NotifyConfig, *, run_dir: Path) -> list[Notifier]`
in `pbv.notify`. Every notifier catches its own errors and raises
`PbvError(code="NOTIFY_FAIL")` with a secret-free message. The orchestrator
catches that and appends to `report.notify_errors`. A notifier failure never
changes VM or run status or the exit code.

`when` per notifier: `always`, `failure` (status in warn/fail/error, or
interrupted, or any `cleanup_ok == False`), or `never`. `run_finished` is
sent when `when` matches the run status. `vm_finished` is sent only when
`per_vm` is set and `when` matches that VM.

Common rendering (`pbv.notify.render`): a subject such as
`[pbv] FAIL 1/4 VMs on restore01 (3 pass, 1 fail)` and a plain-text body
with one block per VM: name, VMIDs, status, backup volid/age/size, failed
step or checks with summaries, sanitize notes count, cleanup state and
`MANUAL CLEANUP REQUIRED` lines first. The text is deterministic (tested
with snapshot-style asserts).

- **Email**: `smtplib` with STARTTLS (default; uses
  `ssl.create_default_context()`), implicit SSL, or none. Optional login.
  `text/plain` UTF-8; screenshots (PNG) attached when `attach_screenshots`,
  at most 5 and 10 MiB total. The `SMTP` factory is injectable for tests.
- **ntfy**: `POST {server}/{topic}` with headers `Title`, `Priority`
  (`priority_ok`/`priority_fail`), `Tags` (no Markdown header: the body is plain text), optional `Click`,
  and `Authorization: Bearer <token>`. The body is the rendered text,
  ≤ 4 KiB (truncated, with a note). When `attach_screenshots`, each PNG is
  sent with `PUT {server}/{topic}` with `Filename` (at most 3). Uses
  `urllib`; the opener is injectable. 429/5xx are retried twice with backoff.
- **JSON**: `report_to_dict(report)` from `pbv.core`, written atomically
  (`tmp` + `os.replace`, mode 0640) to `{dir}/{run_id}.json`, plus
  `latest.json` when `write_latest`. During the run, `vm_finished` rewrites
  `{dir}/{run_id}.partial.json`, which is removed at `run_finished`.
  Retention: keep the newest `keep` `*.json` reports, never deleting
  `latest.json`. `stdout = true` also prints the JSON to stdout.
- **Telegram** (legacy parity): `sendMessage` as plain text (no
  parse_mode), with optional `message_thread_id`. ≤ 4096 chars.

`send_test(notifiers)` sends a synthetic PASS report through every notifier
and returns a `{name: "ok" | "<error>"}` dict (used by `pbv notify-test`).

## 7. JSON report (schema_version 1)

The top level is `RunReport` fields plus `counts`, as produced by
`pbv.core.report_to_dict`. The enums are lowercase strings and the times are
ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ`. Consumers key on `status`, `counts`,
`vms[].status`, `vms[].failure_code`, `vms[].cleanup_ok` and
`vms[].checks[].status`.

## 8. CLI (`pbv`, entry point `pbv.cli:main`)

```
pbv [-c CONFIG] [-v|-q] <command>
  run [--vmid N ...] [--dry-run] [--no-notify]   full cycle (default command)
  preflight                                     run guards, print results
  list-backups [--vmid N ...]                   newest backup per VM (+age)
  cleanup [--include-kept] [--yes]              sweep temp VMs on the restore node
  check-config                                  load + validate config only
  notify-test                                   send a test notification
  --version
```

The default config is `/etc/pbv/config.toml` (env `PBV_CONFIG`). `--vmid`
VMIDs that are not in the config use `Config.vm_target` defaults. Selection
`all` means every VMID that has a backup on `backup_storage`, minus
`run.exclude`. `--dry-run` runs preflight and backup resolution and prints the
plan, but creates nothing and sends nothing.

Exit codes: `0` the run passed (WARN allowed unless `run.fail_on_warn`), `1`
any VM fail/error, `2` config/preflight error, `3` cleanup failure (takes
precedence over 1), `4` lock held, `130` interrupted.

## 9. PVE client (`pbv.pve`)

`PveClient(host, node, token_id, token_secret, *, port=8006, verify_tls=True,
ca_file="", fingerprint="", timeout_s=30, retries=3, sleep=time.sleep,
opener=None)` implements `PveApi`.

- Auth header: `Authorization: PVEAPIToken=<token_id>=<secret>`. The secret
  never appears in a log, an exception message or `repr`.
- TLS: by default the system CA store (or `ca_file`). With `fingerprint` set,
  chain verification is skipped and the leaf certificate's SHA-256 must equal
  the pin; a mismatch → `ApiError(code="TLS_PIN_MISMATCH")`. With
  `verify_tls=false` and no pin, the client logs a warning once.
- Requests are form-encoded (`application/x-www-form-urlencoded`). Lists
  repeat the key (`command=a&command=b`). Booleans become `1`/`0`. Path
  segments are URL-quoted (volids contain `:` and `/`).
- Errors: parse the `{"errors": {...}, "message": ...}` body. Raise
  `ApiError(status, transient)`. Transient: connection refused/reset, timeout,
  HTTP 502/503/504 and 500 whose message contains "got timeout". Retries apply
  to transient errors on GET, and on any method for connection-refused
  *before the request was sent*. The backoff is 1, 2, 4 s ×jitter. Non-GET
  requests are never retried after a send, to avoid double restore/start.
- `wait_task`: poll `GET /nodes/{n}/tasks/{upid}/status` every 2 s until
  `status == stopped`. On a non-OK `exitstatus`, include the last 20 lines of
  `/tasks/{upid}/log` in `TaskResult.log_tail`. `ok` is True for `OK` and
  `WARNINGS: n` (decided at integration). Timeout raises
  `PbvTimeoutError`. `wait_task` does not raise `TaskFailedError` itself;
  callers inspect `ok`.
- Guest agent: `agent/ping` returns False on HTTP 500 "not running"/"No QEMU
  guest agent" errors. `agent/exec` POSTs `command` as a repeated list (plus
  `input-data`) and returns the pid. `agent/exec-status` base64-decodes
  `out-data`/`err-data` when PVE returns them encoded (PVE already decodes;
  accept both, invalid base64 → raw text). `agent/file-write`: the content is
  base64-encoded by us with `encode=0`. PVE's maxLength of 61440 applies to the
  encoded text, so raw content > 46080 bytes → `GuestAgentError`. The config
  loader enforces the same limit.
- `PveGuestAgent(api, vmid, *, sleep, clock, poll_s=1.0)` implements
  `GuestAgent`: `exec` polls exec-status until exited or `timeout_s`, and
  returns `ExecResult(timed_out=True, exitcode=None)` on timeout. `os_family`
  maps osinfo `id == "mswindows"` → WINDOWS, any other non-empty id → LINUX,
  and returns UNKNOWN otherwise. `ip_addresses` skips loopback and link-local
  and returns IPv4 first.
- (Superseded by §1a: screendump goes through NodeShell. ConsoleCapture
  wraps a NodeShell.) `ConsoleCapture(api, *, mode, remote_dir, local_dir, ssh_host, ssh_user,
  ssh_port, ssh_key_file, ssh_known_hosts_file, run=subprocess.run)`. It runs
  HMP `screendump <remote_dir>/<name>.png -f png` through `monitor`. In mode
  `local` it moves the file. In mode `ssh` it fetches the file with `scp`
  (`-o BatchMode=yes -o StrictHostKeyChecking=yes`, plus
  `UserKnownHostsFile` when set), then removes it over `ssh`. If the result
  is not a PNG, it retries without `-f png` (PPM) and converts with
  `pnmtopng`/`convert` if available. It never raises; it returns None and
  logs the reason.

## 10. Logging

The stdlib `logging` logger tree is `pbv.*`. The CLI configures stderr (INFO,
or DEBUG with -v), `run.log_dir/<run_id>/run.log` and per-VM
`run.log_dir/<run_id>/<vmid>/vm.log`, which is also the VM's `work_dir` for
artifacts. Log lines are `KEY=value` style like the legacy script
(`RESTORE_OK vmid=105 temp=900105 dur=81s`). Secrets are never logged.
`run_id` = `YYYYMMDDTHHMMSSZ-<4 hex>`.

## 11. Acceptance tests (numbered; each must be proven by at least one test)

- A1 Preflight refuses a clustered node when require_standalone; refuses a
  forbidden cluster name; refuses a bridge with ports or an IP; refuses a
  non-pbs backup storage; refuses untagged VMs in the temp range.
- A2 Happy path: the newest backup is chosen by ctime; restore is called with
  the temp VMID, target storage and unique=1; mark + sanitize run before start;
  checks run; the VM is destroyed; the report status is pass; exit 0.
- A3 The destroy guard refuses a VMID outside the range or without the tag
  (unless this run created it); `SafetyError` is reported, never destroyed.
- A4 Restore task failure → RESTORE_FAIL, and the partially created locked VM
  is still cleaned up (skiplock retry); the run continues to the next VM.
- A5 A restore timeout calls stop_task and cleans up.
- A6 Boot timeout → BOOT_TIMEOUT, screenshot attempted, checks skipped,
  cleanup runs.
- A7 Destroy failure after retries → cleanup_ok False, exit code 3, MANUAL
  CLEANUP line in notifications.
- A8 Sanitize: every rule in §3 has a test, including set/delete disjointness
  and that the cloud-init drive is preserved.
- A9 An unexpected exception in one VM → INTERNAL_ERROR for that VM, the
  next VM still runs.
- A10 Interrupt during checks → cleanup completes, report interrupted,
  exit 130. A signal during cleanup does not abort cleanup.
- A11 The startup sweep destroys tagged leftovers, skips `pbv-keep`, and never
  touches untagged VMs.
- A12 Check engine: each check type has PASS/FAIL tests on Linux and Windows
  where applicable; non-critical → WARN; wait_s retries; timeout; OS skip;
  agent error → ERROR; shell-injection inertness; script upload path and
  env; host_script process-group kill on timeout.
- A13 Discovery: Linux and Windows signatures, the discovery-error path, mode
  semantics and name de-duplication.
- A14 PveClient: auth header, form encoding with list repetition, URL
  quoting of a volid, error parsing, transient retry on GET only, no retry
  of POST after send, wait_task success/failure/timeout with log tail,
  fingerprint pin match/mismatch, secret absent from repr/errors. Tested
  against a local `http.server` over TLS with a self-signed cert generated
  by `openssl` in a fixture (skip if openssl is missing).
- A15 Notifiers: `when` semantics; email STARTTLS/login/attachments with a
  fake SMTP; ntfy headers/auth/truncation/retry with a local HTTP server;
  JSON atomic write, latest, partial lifecycle and retention; a notifier
  error is recorded in notify_errors and doesn't change the exit code.
- A16 Config: every section validates; unknown keys, inline secrets and
  world-readable secret files are rejected; script paths resolve relative to
  the config file.
- A17 The lock is held → exit 4, nothing called on the API.

## 12. Repository layout

```
src/pbv/core.py          frozen contract (architect)
src/pbv/config.py        frozen config loader (architect)
src/pbv/testing/fakes.py frozen fakes (architect)
src/pbv/pve/             worker: PveClient, PveGuestAgent, ConsoleCapture
src/pbv/checks/          worker: CheckEngine + check implementations + discovery
src/pbv/notify/          worker: render, email, ntfy, json, telegram, build_notifiers, send_test
src/pbv/orchestrator/    worker: Runner, preflight, sanitize, cleanup, lock, signals
src/pbv/cli.py           architect wiring
tests/<pkg>/             tests per package; tests/e2e/ architect/E2E worker
examples/config.toml     annotated example
legacy/                  original bash script, kept for reference
```
