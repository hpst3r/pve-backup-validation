# Brief: `pbv.checks` — check engine, check types, service discovery

Implement SPEC §5 fully. Public API (re-export from `src/pbv/checks/__init__.py`):

```python
class CheckEngine:  # implements pbv.core.CheckSuite
    def __init__(self, config_dir: Path, global_checks: Sequence[CheckSpec] = (), *,
                 host_env: Mapping[str, str] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 retry_interval_s: float = 3.0,
                 should_stop: Callable[[], bool] = lambda: False,
                 run_host: Callable[..., subprocess.CompletedProcess] | None = None) -> None: ...
    def plan(self, target: VmTarget, guest: GuestAgent, os: OsFamily) -> list[CheckSpec]: ...
    def run(self, spec: CheckSpec, guest: GuestAgent, ctx: CheckContext) -> CheckResult: ...
    warnings: list[str]   # plan-time warnings (e.g. auto mode ignoring target.checks), cleared per plan()

LINUX_SIGNATURES: tuple[Signature, ...]
WINDOWS_SIGNATURES: tuple[Signature, ...]
def discover(guest: GuestAgent, os: OsFamily, *, timeout_s: float = 60) -> list[CheckSpec]: ...  # never raises
```

Design:
- One module per concern: `engine.py` (plan/run/retry/status mapping), `linux.py`, `windows.py`
  (command builders + output parsers), `scripts.py` (script/host_script), `discovery.py`.
  Command builders are pure functions returning argv lists — unit-test them directly.
- Linux guest commands use `["/bin/sh", "-c", script]` only where a pipeline is needed; every interpolated
  value is `shlex.quote`d. Windows uses
  `["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]`
  with PowerShell single-quoted literals (`'` doubled). Prove injection inertness: a unit name / path like
  `x; touch /tmp/pwned` or `x'; Remove-Item C:\ -Recurse; '` ends up as one quoted token (assert on argv text).
- Parsing must be robust to: CRLF output (Windows), trailing whitespace, empty output, localized netstat headers.
- `ss -ltnH` lines: match the local address column ending in `:<port>` (IPv4 `0.0.0.0:22`, IPv6 `[::]:22`, `*:22`),
  NOT a substring like `:2222`. Same for netstat. Write table-driven tests.
- HTTP check: build one guest command that prints a machine-parseable result, e.g. `PBV_HTTP <code>` and
  (when body_regex) the body base64'd or after a delimiter, capped at 64 KiB; parse in Python. Accept rules per SPEC.
  If neither curl nor wget → print `PBV_NOCLIENT` → fallback tcp_listen → WARN (or FAIL if port not listening).
  Windows: Invoke-WebRequest with `-SkipCertificateCheck` on PS7 or ServicePointManager callback on PS5.1 —
  emit a script that handles both; `-MaximumRedirection 0` + catch the WebException to read the 3xx/401/403 status.
- script check: read file bytes (params["path"] absolute), `guest.write_file(dest, data)`, then exec. Linux dest
  `/tmp/pbv-<run_id>-<n>-<basename>` where n = per-engine counter; chmod not needed since we call the interpreter
  explicitly. Linux env via `["/usr/bin/env", "K=V", ..., interpreter, dest, *args]`. Windows: wrap in a
  PowerShell `-Command` that sets `$env:K='V'` for each var then invokes the interpreter by extension
  (`.ps1` → `& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '<dest>' args…; exit $LASTEXITCODE`,
  `.cmd/.bat` → `& cmd.exe /c '<dest>' args…`), else powershell -File. A custom `interpreter` param (non-empty)
  overrides: argv = shlex.split(interpreter) + [dest, *args] on Linux. Cleanup: best-effort delete afterwards
  (errors ignored, logged at DEBUG). Exit code mapping + stdout_regex per SPEC.
- host_script: `run_host` defaults to a function using subprocess.Popen(start_new_session=True) with
  timeout → os.killpg(SIGTERM), wait 5 s (use injected clock/sleep only for the grace loop if feasible; a real
  short sleep is fine in that one test), then SIGKILL. Env = {PATH, LANG, HOME from os.environ} + host_env +
  PBV_* vars + spec env. cwd = ctx.work_dir (create it). Capture stdout/stderr (cap 64 KiB each), write full
  output to `ctx.work_dir / f"{safe_check_name}.out"`.
- PBV_* env vars exactly as SPEC §5 "Script environment" for both script and host_script.
- Retry semantics: attempt; if not PASS and the result is retryable (FAIL/WARN, not SKIPPED/ERROR from config issue),
  and clock()-start < wait_s and not should_stop(): sleep(retry_interval_s), retry. ERROR from agent failure is also
  retried within wait_s (the guest may still be booting services). attempts counted.
- Status mapping: critical failure → FAIL, non-critical failure → WARN; warn_exit → WARN regardless;
  agent error → ERROR if critical else WARN; SKIPPED for only_os mismatch (summary says why) and for the
  `ctx.os == UNKNOWN` + OS-specific check case (summary "OS unknown").
- summary ≤ 200 chars single line; detail ≤ 8192 bytes keeping the tail with a "[…truncated N bytes]" prefix.
- Discovery per SPEC: Linux via systemctl list-unit-files; Windows via
  `Get-CimInstance Win32_Service -Filter "StartMode='Auto'" | Select -Expand Name` (or Get-Service where StartType Automatic);
  wildcard alternatives like `postgresql@*`; results de-duplicated; each signature yields service check + port check
  (http for http signatures, tcp_listen otherwise; port 0 → service check only). Names: `"systemd:<unit>"`,
  `"tcp_listen:<port>"`, `"http:<port>"`, `"windows_service:<name>"` — de-dup by name in plan.
- plan(): order and de-dup per SPEC §5; global checks are always appended; OS filtering happens in run (SKIPPED),
  not in plan, so the report shows them.

Tests in `tests/checks/` using `pbv.testing.fakes.FakeGuest` (script responses by argv predicate) — no real VMs.
Cover A12 and A13 completely; include table-driven parser tests and an end-to-end `CheckEngine.run` per type for
Linux and Windows. Use a fake clock/sleep for retries/timeouts. host_script tests may use real `/bin/sh` scripts
in tmp_path (keep them < 3 s total).
