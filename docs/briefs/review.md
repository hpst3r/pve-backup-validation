# Brief (wave 2): adversarial review — whole `pbv` codebase (READ-ONLY for production code)

You are the independent reviewer. Read docs/SPEC.md (authoritative; §1a is a late amendment — two other workers
are implementing it in parallel in `pbv.pve` console/NodeShell and orchestrator sanitize/preflight, so do NOT report
the currently-failing `tests/pve/test_console.py` and `tests/orchestrator/test_runner.py` NodeShell/`shot.mode`
breakage — that is known). Review everything else: `src/pbv/{core,config,cli}.py`, `src/pbv/pve`,
`src/pbv/checks`, `src/pbv/notify`, `src/pbv/orchestrator` (lifecycle/cleanup/sweep/signals/lock logic).

Focus, in priority order:
1. Safety: can pbv ever stop/destroy/modify a VM that is not its own temp VM? (guard bypasses, VMID arithmetic,
   tag parsing (`;` vs `,` separators, case), sweep logic, `created_by_run` misuse, race between check and act).
   Can it ever talk to a node other than target.node?
2. Cleanup guarantees: any path where a restored VM is left behind without being reported (`cleanup_ok`),
   including exceptions inside cleanup, interrupts, notifier exceptions, logging failures, KeyboardInterrupt
   (BaseException!) vs the StopFlag handler.
3. Error handling: exceptions that escape where SPEC says "never raises"; wrong error codes/status mapping;
   retry of non-idempotent POSTs; timeouts not enforced; exit-code precedence.
4. Injection: guest shell/PowerShell command construction, ssh remote strings, HMP commands, ntfy headers
   (CR/LF in titles), email headers.
5. Secrets: token/password leakage into logs, reprs, exceptions, JSON report, notifications.
6. PVE API correctness vs. real Proxmox VE 8/9 behaviour (endpoint paths, param names, response shapes:
   e.g. agent exec-status fields, task status, storage content fields, `delete` param format, tags format).
   Use the PVE API viewer knowledge you have; flag uncertainties as such.
7. Spec drift / CLI wiring bugs in `src/pbv/cli.py` (it was written against briefs before workers finished:
   check every call matches the real APIs — e.g. preflight return type, PreflightFailure, Runner signature,
   ConsoleCapture.from_config, exit codes).

Method: prove each real finding with a focused failing test under `tests/review/` named `test_<area>_review.py`,
gated so the suite stays green by default:
```python
import os, pytest
REVIEW = os.environ.get("PBV_REVIEW") == "1"
def review_bug(reason): 
    if not REVIEW: pytest.skip("BUG: " + reason)
```
Call `review_bug("...")` at the top of each failing test (so `PBV_REVIEW=1 pytest tests/review` shows exactly what
is broken). Tests must fail for the right reason when PBV_REVIEW=1. Findings you cannot prove with a unit test
(e.g. real-PVE behaviour) go in contract_issues marked [UNPROVEN].
You may only create files under `tests/review/`. Commit them.

Report each finding in `contract_issues` as
`[SEVERITY critical|high|medium|low] path:line — problem — evidence (test name or reasoning) — minimal fix`.
Be concrete and skeptical; no style nits. Aim for the 10–25 most important findings.
