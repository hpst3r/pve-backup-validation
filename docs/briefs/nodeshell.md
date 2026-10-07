# Brief (wave 2): `pbv.pve` — NodeShellRunner + ConsoleCapture rework

The contract changed after wave 1 (read SPEC §1a and `pbv.core.NodeShell`, `pbv.config.NodeShellConfig`,
`pbv.config.ScreenshotConfig` — now only `enabled` and `when`). On PVE 9 HMP `screendump` and removing non-mapped
passthrough are root@pam-only, so they go through a root shell on the restore node, not the API.
Currently `tests/pve/test_console.py` fails (13 tests) because `ConsoleCapture.from_config` reads removed fields.
You own `src/pbv/pve/` and `tests/pve/` only.

Implement (re-export from `pbv.pve`):

```python
class NodeShellRunner:  # implements pbv.core.NodeShell
    def __init__(self, cfg: NodeShellConfig, *, node: str,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 which: Callable[[str], str | None] = shutil.which,
                 geteuid: Callable[[], int] = os.geteuid,
                 wall_clock: Callable[[], float] = time.time) -> None: ...  # ConfigError if mode == "off"
    @classmethod
    def from_config(cls, cfg: NodeShellConfig, *, node: str, **kw) -> "NodeShellRunner | None": ...  # None if off
    def probe(self) -> str: ...
    def qm_set(self, vmid: int, set_: Mapping[str, str], delete: Sequence[str]) -> None: ...
    def screendump(self, vmid: int, dest: Path) -> Path | None: ...   # never raises

class ConsoleCapture:  # implements pbv.core.ConsoleCapturer, thin adapter
    def __init__(self, shell: NodeShell) -> None: ...
    @classmethod
    def from_config(cls, shell: NodeShell | None, shot: ScreenshotConfig) -> "ConsoleCapture | None": ...  # None unless shot.enabled and shell
    def capture(self, vmid: int, dest: Path) -> Path | None: ...  # delegates to shell.screendump
```

Requirements:
- `local` mode: runs `qm` directly via `run([...], capture_output=True, timeout=cfg.timeout_s, check=False)`.
  probe(): geteuid()==0 and which("qm") else NODE_SHELL_FAIL with a clear message ("pbv must run as root on the
  restore node for node_shell.mode = local" / "qm not found: is this a PVE node?").
- `ssh` mode: argv `["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
  "-p", port, (+ "-i", key, "-o", "IdentitiesOnly=yes" if key) (+ "-o", f"UserKnownHostsFile={kh}" if kh),
  f"{user}@{host}", "--", remote_command_string]`. The remote command string is built with `shlex.join` of the qm
  argv (ssh concatenates args into one shell string — never pass unquoted values). probe() runs `qm list` with
  ssh (proves auth + qm present + root-ish) and returns "ssh root@host: ok".
- `qm_set(vmid, set_, delete)`: argv `["qm", "set", str(vmid)] + [f"--{k}", v for each set (sorted)] +
  (["--delete", ",".join(sorted(delete))] if delete)`. Reject keys not matching `^[a-z][a-z0-9_-]*$` (ConfigError-ish
  PbvError NODE_SHELL_FAIL, defensive) and vmid not int. No-op when both empty. Non-zero exit / timeout / OSError →
  `PbvError(code="NODE_SHELL_FAIL")` message `"node shell: qm set <vmid> failed (exit N): <last stderr line ≤200>"`.
- `screendump(vmid, dest)`: remote file `{remote_dir}/pbv-{vmid}-{int(wall_clock())}.png`; validate remote_dir
  matches `^/[A-Za-z0-9_./-]*$` at construction (ConfigError). Command: `qm monitor <vmid>` reading the HMP command
  from stdin — `run(argv, input=f"screendump {remote} -f png\n".encode(), ...)` (local) or for ssh the same argv
  wrapped in ssh with stdin input. Ensure `mkdir -p remote_dir` first (local: os.makedirs; ssh: prepend
  `mkdir -p <dir> && ` inside the remote string, quoted). Then: local → shutil.move to dest.png; ssh → `scp` with
  the same -o options (`-P port`) to dest.png, then `ssh ... rm -f <remote>` best-effort. Validate PNG magic; if not
  PNG, retry once without `-f png` (PPM, `.ppm`), and convert with `pnmtopng` or `convert` if `which` finds one.
  Never raises: log WARNING with the reason and return None. Reuse/refactor the wave-1 logic in
  `src/pbv/pve/console.py` (keep good parts, delete the API-monitor path for screendump — the API `monitor()` method
  on PveClient stays, it's still used for info commands).
- Remove the API-based ConsoleCapture constructor params (mode/remote_dir/ssh_*); rewrite `tests/pve/test_console.py`
  for the new shape and add `tests/pve/test_nodeshell.py`: argv shape incl. quoting of hostile values
  (`description=$(rm -rf /)`-style values must appear as a single quoted token in the ssh remote string — assert by
  `shlex.split(remote) == expected_qm_argv`), probe success/failure (local euid != 0, qm missing, ssh exit 255),
  qm_set failure message/stderr tail, timeout, screendump local/ssh PNG + PPM fallback + converter missing,
  remote cleanup attempted even when scp fails, from_config None when off.
- Never log secrets (there are none here except key file paths, which are fine).
- Keep all other tests/pve passing; ruff clean.
