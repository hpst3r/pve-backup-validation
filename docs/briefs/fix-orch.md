# Brief (fix wave): `pbv.orchestrator` — review findings + contract updates

You own `src/pbv/orchestrator/`, `tests/orchestrator/`, and `tests/review/test_orchestrator_review.py`.
Read SPEC §1, §1a, §4 and §8 (all amended), plus `pbv.core.NodeShell` (now `probe`, `unlock`, `sysctl`, `qm_set`,
`screendump`) and `pbv.testing.fakes`. FakePve now rejects `skiplock` like real PVE (root@pam only, verified in
qemu-server), so 4 tests in tests/orchestrator/test_runner.py currently fail.

Review gating: tests under `tests/review/` call `review_bug("...")`, which skips unless `PBV_REVIEW=1`. For each finding
you fix, DELETE that `review_bug(...)` line in the matching review test (you may edit only the review tests for your
findings) and make it pass without weakening its assertions; add regression tests in your own `tests/<pkg>/`.
Verify with `PBV_REVIEW=1 .../python -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests/review/<file>`
(exporting is blocked; use `env PBV_REVIEW=1 ...`). Then run the WHOLE suite
(`... -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests`), which must pass apart from review
tests owned by other fix workers, which stay skipped by default. Ruff check and format must be clean.

Fix:
1. [contract] Locked VMs during cleanup (SPEC §4 step 1): never send skiplock via the API. If the config has
   `lock` and the VM is ours: call `node_shell.unlock(vmid)` when node_shell exists, else fail the attempt with
   code VM_LOCKED and the hint from the SPEC. Retries/backoff unchanged. Update the 4 failing tests (A4, A5) so
   they use FakeNodeShell, and add a test without node_shell that ends in CLEANUP_FAIL with VM_LOCKED in the message.
2. [high] Cleanup must run in a `finally` that also covers BaseException (KeyboardInterrupt/SystemExit) and the
   screenshot step. KeyboardInterrupt inside a VM: record that VM as ERROR INTERRUPTED, finish its cleanup, mark
   the remaining VMs NOT_RUN, set report.interrupted=True, still call run_finished, and RETURN the report (the CLI
   maps it to 130). SystemExit and other BaseExceptions: run the cleanup, then re-raise. Tests:
   test_cleanup_runs_when_lifecycle_raises_base_exception, test_cleanup_runs_when_screenshot_step_raises.
3. [high] Restore POST raising ApiError (any status, since the request may have been processed) → add temp to
   created_by_run so cleanup checks vm_exists and destroys it if present (test_restore_post_5xx_after_send_still_cleans_up).
   Make sure that a 4xx error caused by "VM already exists" for a VMID that is NOT ours can't lead to destroying a
   foreign VM. The guard rule from SPEC §1 still requires the range, and the temp_vmid step already refuses busy
   untagged VMIDs before restore. Add a test proving an untagged pre-existing temp VMID is never destroyed even if
   restore raises.
4. [high] sweep_failures: if this is already done (orchns), confirm test_sweep_failure_is_reported passes, run status
   ERROR, exit 3.
5. [medium] keep_on_failure only when the `sanitize` step PASSED; otherwise destroy, and note "not kept: sanitize
   failed" (test_keep_on_failure_never_keeps_unsanitized_vm_on_production_bridge).
6. [medium] Preflight bridge guard per amended SPEC §1 guard 3: reject `method`/`method6` other than absent/manual,
   and `gateway6`. When node_shell is provided, also `node_shell.sysctl(f"net.ipv6.conf.{bridge}.disable_ipv6")` must
   be "1", else PREFLIGHT_FAIL with a hint (`echo 'net.ipv6.conf.<br>.disable_ipv6 = 1' > /etc/sysctl.d/90-pbv.conf;
   sysctl --system`). Without node_shell, add a WARN step `bridge_ipv6` saying it can't be verified (non-fatal).
   (test_preflight_rejects_bridge_that_obtains_an_address[*])
7. [medium] Interrupt observed after the last check or during the final cleanup → report.interrupted=True, exit 130
   (test_interrupt_during_last_check_marks_report_interrupted, test_signal_during_final_cleanup_is_reported). Check
   should_stop after `_run_vms` and after `_prepare`; StopFlag.count>0 also counts.
8. [low] exit_code precedence 3 > 130 > 2 > 1 > 0 (SPEC §8 amended). Update tests.
9. [low, from review #17] Preflight node_shell step: after probe(), run `node_shell.sysctl("kernel.hostname")`
   and require it to equal `cfg.target.node` (PVE node name == short hostname; compare the part before the first
   dot). Mismatch → PREFLIGHT_FAIL "node_shell reaches host X, expected Y". Test both. (FakeNodeShell.sysctls is a
   dict you can set in tests.)
Acceptance: all tests/orchestrator pass; the orchestrator review tests pass with PBV_REVIEW=1 (except any you
document as intentionally different in contract_issues); full suite green.
