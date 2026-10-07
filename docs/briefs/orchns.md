# Brief (wave 2): `pbv.orchestrator` — integrate NodeShell + resolve wave-1 contract issues

The contract changed after wave 1. Read SPEC §1a, `pbv.core` (NodeShell, PreflightError.steps,
RunReport.sweep_failures, CheckSuite.run docstring), `pbv.config` (NodeShellConfig; ScreenshotConfig is now just
`enabled` + `when`; `Config.node_shell`), and `pbv.testing.fakes` (FakeNodeShell, FakePve.token_is_root —
default False: FakePve now REJECTS API changes to privileged keys and the screendump monitor command, like PVE 9).
Currently 33 tests in `tests/orchestrator/test_runner.py` fail (they reference `shot.mode`). You own
`src/pbv/orchestrator/` and `tests/orchestrator/` only. Do not touch pbv.pve (another worker is rewriting
ConsoleCapture in parallel; you only see the ConsoleCapturer protocol).

Changes:
1. `Runner(..., node_shell: NodeShell | None = None)`. Screenshot step: run when `self.console is not None and
   cfg.screenshot.enabled` (+ existing when/failure logic). Drop every `screenshot.mode` reference.
2. Sanitize split per SPEC §1a: add to `sanitize.py` a pure `split_privileged(plan, current_cfg) -> (api_set,
   api_delete, root_set, root_delete)` using the regex `^(?:(?:hostpci|usb|serial|parallel|virtiofs)\d+|args|hookscript)$`
   (define it in orchestrator; mirror of fakes.PRIVILEGED_KEY), with the exception that `serial*` stays on the API
   side if both the current and new value are `socket`. Apply API part via one `update_vm_config`, then root part
   via one `node_shell.qm_set`. If root part non-empty and node_shell is None → step `sanitize` FAIL code
   `SANITIZE_NEEDS_ROOT`, message `"needs root@pam for: hostpci0, usb1 — configure [node_shell]"` (VM status FAIL;
   cleanup still runs). NODE_SHELL_FAIL from qm_set → sanitize ERROR with that code.
   Note: mapped hostpci (`mapping=`) could be removed via API with Mapping.Use, but just send ALL hostpci/usb via
   root when node_shell exists; when node_shell is None and the device is mapped-only (`mapping=` and no `host=`),
   still try the API (it may work) — i.e. only classify as root-required when value contains `host=` or for usb
   `host=`, or for serial non-socket, args, hookscript, parallel, virtiofs. Test both branches.
3. Preflight: `preflight(api, cfg, node_shell=None)`. Add step `node_shell` after `version` when
   cfg.node_shell.mode != "off": call `node_shell.probe()`; failure → PREFLIGHT_FAIL (fatal, message from the
   error). If mode != off but node_shell is None → fatal PREFLIGHT_FAIL "node_shell configured but not provided".
   Replace your `PreflightFailure` with the core `PreflightError(..., steps=...)` (keep `PreflightFailure` as an
   alias subclass for compatibility or remove it — update tests either way; the CLI will catch PreflightError).
4. Sweep: per-VM sweep failures go to `report.sweep_failures` as `"<temp vmid>: <code> <message>"` and make the
   run status ERROR + `exit_code` 3 (a leftover temp VM still exists). `Runner.sweep()` return value unchanged;
   expose failures via a new attribute `last_sweep_failures: list[str]`.
5. Interrupt inside a check: after every `checks.run(...)` call check `should_stop` and raise InterruptedRun
   (already partly there; confirm with a test where the fake check suite sets the stop flag mid-run).
6. Tests: restore green; add tests for every item above using FakeNodeShell and FakePve(token_is_root=False),
   including: VM with `hostpci0: host=0000:01:00.0` + node_shell → qm_set called with delete hostpci0 and VM boots;
   same without node_shell → SANITIZE_NEEDS_ROOT, cleanup ran; screenshot uses console only when enabled;
   preflight node_shell probe failure; sweep failure → exit 3.
Ruff clean; whole suite for your package < 30 s.
