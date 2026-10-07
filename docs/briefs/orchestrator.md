# Brief: `pbv.orchestrator` — preflight, sanitize, lifecycle, cleanup, sweep, lock, signals

Implement SPEC §1–§4 and §10 (logging for the run). Public API (re-export from `src/pbv/orchestrator/__init__.py`):

```python
@dataclass(frozen=True)
class SanitizePlan: set: dict[str, str]; delete: list[str]; notes: list[str]; warnings: list[str]

def sanitize_config(cfg: Mapping[str, str], *, bridge: str, storages: set[str], opts: pbv.config.SanitizeConfig,
                    vmid: int) -> SanitizePlan: ...
def preflight(api: PveApi, cfg: pbv.config.Config) -> list[StepResult]: ...   # raises PreflightError on first fatal guard
def new_run_id(now: datetime | None = None) -> str: ...                       # YYYYMMDDTHHMMSSZ-xxxx

class RunLock:   # context manager; fcntl.flock LOCK_EX|LOCK_NB; raises PbvError(code="LOCKED") if held
    def __init__(self, path: Path) -> None: ...

class StopFlag:  # signal handling helper
    def install(self) -> None: ...      # SIGINT/SIGTERM → set flag; restores previous handlers on uninstall()
    def uninstall(self) -> None: ...
    def __call__(self) -> bool: ...     # should_stop
    in_cleanup: bool                    # while True, signals are recorded (count) but never raise

class Runner:
    def __init__(self, cfg: pbv.config.Config, api: PveApi, checks: CheckSuite, notifiers: Sequence[Notifier], *,
                 guest_factory: Callable[[int], GuestAgent],
                 console: ConsoleCapturer | None = None,
                 run_id: str | None = None,
                 should_stop: Callable[[], bool] = lambda: False,
                 stop_flag: StopFlag | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 log_dir: Path | None = None,
                 tool_version: str = "") -> None: ...
    def resolve_targets(self, vmids: Sequence[int] | None = None) -> list[VmTarget]: ...
    def plan(self, vmids=None) -> list[tuple[VmTarget, BackupRef | None]]: ...   # for --dry-run (no mutations)
    def run(self, vmids: Sequence[int] | None = None) -> RunReport: ...          # full cycle incl. preflight, sweep, notify
    def sweep(self, include_kept: bool = False) -> list[int]: ...                # also used by `pbv cleanup`
    def may_destroy(self, vmid: int) -> bool: ...

def exit_code(report: RunReport, *, fail_on_warn: bool = False) -> int: ...      # SPEC §8 (0/1/3/130; 2 is CLI's)
```

Behaviour requirements (all from SPEC; tests must prove each):
- `run()`:
  1. preflight (PreflightError → report with status ERROR, preflight steps recorded, no VM processed, notifiers
     still called with run_finished; caller maps to exit 2 — expose `report.preflight[-1].error_code == "PREFLIGHT_FAIL"`).
  2. sweep leftovers if configured.
  3. per VM lifecycle exactly as the SPEC §2 table, one at a time, with StepResults and failure codes;
     `vm_finished` on every notifier after each VM; `run_finished` at the end. Notifier exceptions (PbvError or any
     Exception) are caught and appended to `report.notify_errors` as "<notifier.name>: <code> <message>".
  4. report status = worst VM status (ERROR if interrupted, preflight failed, or any cleanup failure).
- Restore step: catch ApiError from restore_vm; on PbvTimeoutError from wait_task call `api.stop_task(upid)`
  (errors there logged, ignored) and record RESTORE_TIMEOUT. After a restore attempt that may have created the
  VM (any outcome after restore_vm returned a UPID, and also ApiError with status None — unknown outcome),
  remember the temp vmid as `created_by_run` so cleanup may destroy it even without the tag; check vm_exists in cleanup.
- Mark step: `update_vm_config(temp, set={"tags": merged, "description": marker, "onboot": "0"}, delete=["protection"]
  only if present)`. Merged tags use `;` separator, dedupe, keep existing. Description marker:
  `"pbv temporary restore test of VM {vmid} ({name}) — run {run_id} — safe to delete"`.
- Sanitize: pure `sanitize_config` (§3) over `get_vm_config(temp)`; storages = names from `api.storage_list()`;
  ONE update call; notes → VmResult.sanitized; warnings logged + included in sanitized with "WARNING: " prefix.
  ApiError 403 → message hint per SPEC.
- Start/boot: start task wait 120 s; boot poll every 5 s via injected sleep until boot_timeout_s using clock;
  check vm_status each poll: "stopped" → BOOT_FAIL; should_stop → InterruptedRun.
- Checks: `checks.plan(target, guest, os)` then `checks.run(...)` per spec; CheckContext.work_dir =
  log_dir/<run_id>/<vmid>/ ; between checks test should_stop. If `checks` has a `warnings` attribute, log them.
- Screenshot via `console.capture(temp, work_dir / f"console-{temp}")` per SPEC conditions; append path.
- Cleanup per SPEC §4 with retries/backoff via injected sleep; stop_flag.in_cleanup = True during cleanup;
  may_destroy guard; keep_on_failure semantics (add tag `pbv-keep`, leave running, cleanup_ok stays True,
  add sanitized note "kept for debugging").
- Two consecutive VMs with ApiError(status None) anywhere → remaining VMs recorded ERROR API_UNREACHABLE (not executed).
- Unexpected exception in a VM → INTERNAL_ERROR with `type(exc).__name__: msg`, traceback to the VM log, cleanup runs.
- Interrupt: InterruptedRun raised inside lifecycle → current VM status ERROR code INTERRUPTED, cleanup runs fully,
  remaining VMs not run (not listed, or listed SKIPPED — choose listed SKIPPED with code "NOT_RUN"), report.interrupted.
- Logging: logger `pbv.orchestrator`; per-run file handler `log_dir/<run_id>/run.log` and per-VM handler
  `log_dir/<run_id>/<vmid>/vm.log` attached for the VM's duration (remove after; no handler leaks — test it);
  `VmResult.log_file`. KEY=value style messages. If log_dir is None use cfg.run.log_dir.
- Preflight per SPEC §1 guards 1–6 producing StepResults named `node`, `standalone`, `bridge`, `backup_storage`,
  `target_storage`, `temp_range`; plus a `version` info step (PVE version string). Bridge port check treats
  `bridge_ports` missing/""/"none" as no ports; IP fields: cidr, address, cidr6, address6, gateway, gateway6.
- `resolve_targets`: selection listed → cfg.vms (filtered by vmids if given; unknown vmids via cfg.vm_target);
  selection all → every distinct vmid in list_backups(backup_storage) minus exclude, using cfg.vm_target; sorted.
- `exit_code`: 130 if interrupted; 3 if any cleanup_ok False; 1 if status fail/error (or warn with fail_on_warn);
  2 if preflight failed; else 0.

Tests in `tests/orchestrator/` using `FakePve`, `FakeCheckSuite`, `FakeConsole`, `RecordingNotifier`, and a guest
factory returning a minimal GuestAgent over FakePve (write a tiny adapter in the test — do NOT import pbv.pve).
Fake sleep/clock (a clock advanced by the fake sleep) so boot/cleanup backoff tests are instant.
Cover A1–A11 and A17 completely, plus sanitize table tests (A8) for every rule in SPEC §3.
