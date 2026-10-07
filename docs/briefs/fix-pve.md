# Brief (fix wave): `pbv.pve` — review findings + NodeShell additions

You own `src/pbv/pve/`, `tests/pve/`, and `tests/review/test_pve_review.py`. Read SPEC §1a/§4 and `pbv.core.NodeShell`
(new methods `unlock(vmid)` and `sysctl(key)`); tests/pve/test_nodeshell.py::test_protocol now fails because
NodeShellRunner lacks them.

Review gating: tests under `tests/review/` call `review_bug("...")`, which skips unless `PBV_REVIEW=1`. For each finding
you fix, DELETE that `review_bug(...)` line in the matching review test (you may edit only the review tests for your
findings) and make it pass without weakening its assertions; add regression tests in your own `tests/<pkg>/`.
Verify with `PBV_REVIEW=1 .../python -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests/review/<file>`
(exporting is blocked; use `env PBV_REVIEW=1 ...`). Then run the WHOLE suite
(`... -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests`), which must pass apart from review
tests owned by other fix workers, which stay skipped by default. Ruff check and format must be clean.

Fix:
1. NodeShellRunner.unlock(vmid) → `qm unlock <vmid>` (same local/ssh execution, quoting and error mapping as
   qm_set). NodeShellRunner.sysctl(key) → `sysctl -n <key>`, with key validated against `^[a-z0-9_.-]+$`
   (otherwise NODE_SHELL_FAIL); returns stripped stdout. Tests: argv shape (local + ssh, shlex round-trip), errors.
2. [medium] PveClient: validate token_id and token_secret in __init__ against printable ASCII without
   spaces/CR/LF (`^[\x21-\x7e]+$`); raise ConfigError with no value in the message. Also catch ValueError /
   http.client.InvalidURL-type errors in the request phase and convert them to a secret-free
   ApiError(code="API_BAD_REQUEST"). (test_invalid_header_value_becomes_secret_free_api_error)
3. [contract] PveClient stop_vm/destroy_vm: keep the skiplock parameter in the signature, but the orchestrator no
   longer sends it. Leave as is (document in the docstring that it is root@pam-only on PVE).
4. Double-check the ssh probe: the SPEC says preflight compares `sysctl -n kernel.hostname` with the node (the
   orchestrator does this); just make sure sysctl works for that key.
