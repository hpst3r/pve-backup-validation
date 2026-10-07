# pbv — Proxmox Backup Validation

Automated **test restores** of Proxmox Backup Server (PBS) backups, in the
spirit of Veeam SureBackup. For each configured VM, pbv:

1. finds the newest backup on the PBS storage,
2. restores it to a temporary VM on a **separate, standalone restore node**
   (never your production cluster),
3. sanitizes the config: moves every NIC to an isolated bridge, removes
   PCI/USB passthrough and host devices, ejects ISOs, drops host-specific
   options, and enables the guest agent,
4. boots it and waits for the QEMU guest agent,
5. runs checks inside the guest: systemd / Windows services, listening ports,
   HTTP endpoints, log scans, **arbitrary commands and uploaded scripts**
   (sh / PowerShell / cmd), plus scripts on the runner itself,
6. reports by **email**, **ntfy**, a **JSON report** and (optionally)
   Telegram, with a console screenshot on failure,
7. destroys the temporary VM, retrying and verifying, and loudly reports
   anything it could not remove.

This is a Python rewrite of [Tobidp/pve-backup-validation](https://github.com/Tobidp/pve-backup-validation)
(bash, MIT). The original script is kept in [`legacy/`](legacy/). The
authoritative design document is [`docs/SPEC.md`](docs/SPEC.md).

> **Status:** unit- and fake-tested only. It has not yet been run against a
> real Proxmox VE node. Treat the first real runs as supervised acceptance
> tests.

## Topology

```
production cluster ──backup──▶ PBS ◀──read (PBS storage)── restore node (standalone PVE)
                                                             │  vmbr-pbv: no ports, no IP
pbv runner ──HTTPS API token (+ optional root SSH)───────────┘  temp VMs 900000+<vmid>
```

pbv talks only to the restore node. Before it creates anything, preflight
refuses to run if:

- the node is part of a cluster (`require_standalone`, default on), or its
  cluster name is in `forbid_cluster_names`;
- the isolated bridge has ports or an IP address;
- the backup storage is not of type `pbs`, or the target storage can't hold
  images;
- the temporary VMID range contains a VM pbv didn't tag.

Temporary VMs are `temp_vmid_base + vmid` (default `900000 + vmid`) and carry
the `pbv-temp` tag. Before every stop or destroy, pbv checks the VMID range
and either the tag or the fact that this run created the VM.

### Why there's a root shell option

On PVE 9, only `root@pam` may remove non-mapped PCI/USB passthrough, change
real serial/parallel devices, `args` or `hookscript`, or run the `screendump`
monitor command, and API tokens are never `root@pam`. pbv does just those
operations with `qm` through `[node_shell]`: either locally (pbv runs on the
restore node as root) or over SSH with a pinned host key. Without it, VMs
that need such changes fail with `SANITIZE_NEEDS_ROOT`, and screenshots are
unavailable.

### Disk space

Every test is a full restore, so it needs scratch space on `target_storage`
equal to the VM's disk size. VMs are tested one at a time, and pbv checks free
space first (`min_free_space_ratio`).

## Install

On the runner (the restore node itself, or any Linux host that can reach
it):

```bash
python3 -m venv /opt/pbv/venv
/opt/pbv/venv/bin/pip install git+https://github.com/hpst3r/pve-backup-validation
install -d -m 750 /etc/pbv /etc/pbv/secrets /var/lib/pbv /var/log/pbv
cp examples/config.toml /etc/pbv/config.toml   # then edit
```

On the restore node, as root, review and then run
[`deploy/setup-restore-node.sh`](deploy/setup-restore-node.sh). It creates
the isolated bridge and the `pbv@pve` user, role and API token. Add the
production PBS datastore as a storage first, preferably with a PBS user that
only has `DatastoreReader`, and the encryption key if your backups are
encrypted.

```bash
pbv check-config
pbv preflight
pbv list-backups
pbv run --vmid 105 --dry-run
pbv run --vmid 105
cp deploy/pbv.service deploy/pbv.timer /etc/systemd/system/ && systemctl enable --now pbv.timer
```

## Configuration

See the annotated [`examples/config.toml`](examples/config.toml). Secrets are
only accepted through `*_file` (must not be world-readable) or `*_env`.

Per VM, `mode` decides which checks run:

| mode | checks |
|---|---|
| `auto` | discovered services (Linux: nginx, apache, postgres, mariadb, redis, sshd, …; Windows: IIS, SQL Server, AD DS, DNS, RDP, SMB) |
| `hybrid` | your `[[vm.check]]` entries plus discovered ones |
| `manual` | only your `[[vm.check]]` entries |

`[[global_check]]` entries apply to every VM; use `os = "linux"` or
`os = "windows"` to filter them.

### Check types

| type | what it does |
|---|---|
| `systemd` | `systemctl is-active <unit>`; on failure, includes the status and the journal tail |
| `windows_service` | `Get-Service` status is `Running` |
| `tcp_listen` | socket listening on the port inside the guest (`ss`/`netstat`, `Get-NetTCPConnection`) |
| `http` | request from inside the guest (curl/wget, `Invoke-WebRequest`), checking status and an optional body regex |
| `command` | runs an argv in the guest; checks the exit code and an optional stdout regex |
| `script` | **uploads a local script** into the guest and runs it (`.sh` via `/bin/sh` or your interpreter; `.ps1`/`.cmd`/`.bat` on Windows) |
| `host_script` | runs a script **on the runner**, with the guest's IPs and other facts in the environment |
| `log_scan` | counts error lines in a unit's journal, minus ignore patterns |

Every check accepts `critical` (false → WARN instead of FAIL), `timeout_s`,
`wait_s` (keep retrying until the service comes up), `os` and `name`.
Scripts receive `PBV_RUN_ID`, `PBV_VMID`, `PBV_TEMP_VMID`, `PBV_VM_NAME`,
`PBV_OS`, `PBV_GUEST_IP(S)`, `PBV_TARGET_NODE` and `PBV_CHECK_NAME`, plus the
check's `env` table. Host scripts also get `PBV_WORK_DIR` for artifacts.
Guest scripts are limited to 45 KiB by the guest-agent file-write size.

Guests need `qemu-guest-agent` installed and running. Linux HTTP checks need
curl or wget; without either, pbv falls back to a port check and reports
WARN.

## Exit codes

| code | meaning |
|---|---|
| 0 | all VMs passed (WARN allowed unless `run.fail_on_warn`) |
| 1 | at least one VM failed or errored |
| 2 | config or preflight error; nothing was restored |
| 3 | **a temporary VM could not be removed**; manual cleanup needed (takes precedence over 1) |
| 4 | another pbv run holds the lock |
| 130 | interrupted (cleanup still ran) |

The JSON report (`notify.json.dir`, plus `latest.json`) is written on every
run. It is meant for monitoring; see SPEC §7 for the stable fields.

## Development

```bash
uv venv -p 3.11 .venv && uv pip install -p .venv -e '.[dev]'
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
```

Runtime dependencies: none (stdlib only, Python ≥ 3.11).

## License

MIT. Original bash implementation © 2026 Tobias Pandolfo; see [LICENSE](LICENSE).
