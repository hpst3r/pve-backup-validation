# Brief (fix wave): `pbv.checks` — review findings

You own `src/pbv/checks/`, `tests/checks/`, and `tests/review/test_checks_review.py`.

Review gating: tests under `tests/review/` call `review_bug("...")`, which skips unless `PBV_REVIEW=1`. For each finding
you fix, DELETE that `review_bug(...)` line in the matching review test (you may edit only the review tests for your
findings) and make it pass without weakening its assertions; add regression tests in your own `tests/<pkg>/`.
Verify with `PBV_REVIEW=1 .../python -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests/review/<file>`
(exporting is blocked; use `env PBV_REVIEW=1 ...`). Then run the WHOLE suite
(`... -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests`), which must pass apart from review
tests owned by other fix workers, which stay skipped by default. Ruff check and format must be clean.

Fix:
1. [medium] default_run_host: after the timeout kill, `communicate(timeout=grace_s)`; on TimeoutExpired close the
   pipes, `wait()`, and return the partial output. The run must stay bounded when a grandchild leaves the session but
   still holds stdout (test_default_run_host_bounded_when_grandchild_leaves_session).
2. [medium] Windows script wrapper: a missing interpreter or a script that throws must not exit 0. Use
   `$ErrorActionPreference='Stop'; try { & <interp> ... } catch { Write-Output $_; exit 1 }; if ($null -eq $LASTEXITCODE)
   { exit 1 }; exit $LASTEXITCODE` (but `.ps1` run via `powershell -File` sets LASTEXITCODE; keep that working).
   (test_windows_wrapper_missing_interpreter_is_not_exit_0)
3. [low] InterruptedRun / Kind.ERROR must never be downgraded to WARN by `critical=False`. Only genuine check
   failures are. (test_interrupted_run_on_noncritical_check_is_error_not_warn). Agent errors on non-critical checks
   stay WARN per SPEC; only InterruptedRun and internal errors are the exception.
4. [low] Remove Kind.WARN from RETRYABLE: warn_exit and the no-HTTP-client fallback are final
   (test_warn_exit_is_not_retried_for_wait_s).
5. [low] .cmd/.bat args: the config loader now rejects cmd metacharacters. Additionally quote each arg for cmd.exe
   in the wrapper (wrap in double quotes if it contains spaces). Add a test.
