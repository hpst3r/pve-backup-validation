# Worker rules (read first)

You are implementing ONE Python package of `pbv` in an isolated git worktree.
Read `docs/SPEC.md` (authoritative), `src/pbv/core.py`, `src/pbv/config.py`
and `src/pbv/testing/fakes.py` (the frozen contract) before writing code.
`legacy/backup_validation.sh` is the bash original, for reference only.

Hard rules:
- Edit ONLY `src/pbv/<your pkg>/` and `tests/<your pkg>/`. Do NOT modify
  core.py, config.py, testing/, docs/, pyproject.toml, or other packages. If
  the contract is insufficient, work around it inside your package and report
  it under `contract_issues` (be specific: what, why, proposed change).
- Runtime imports: stdlib, `pbv.core`, `pbv.config` only. Never import a
  sibling worker package (pbv.pve / pbv.checks / pbv.notify / pbv.orchestrator)
  — use the Protocols in core and the fakes in `pbv.testing.fakes`.
- Python 3.11, stdlib only at runtime; tests use pytest only (no new deps).
- No real network or real Proxmox in tests. Local loopback servers
  (http.server / socketserver / smtpd-like fakes on 127.0.0.1, port 0) are OK.
  Inject `sleep`/`clock` so tests never really wait > 1 s; the whole package
  suite must finish in < 30 s.
- Never log, return, or put in exception messages any secret (API token,
  SMTP password, ntfy token).
- Error handling is a primary goal of this rewrite: every failure path in the
  SPEC needs a test; no bare `except:`; `except Exception` only at documented
  boundaries, logging the traceback at DEBUG and converting to a PbvError code.
- Small, readable, typed code; module/class docstrings; an `__init__.py` that
  re-exports the public API the architect will wire (see your brief).
- Tooling (run from the worktree root; the venv is shared and already has the
  package installed in editable mode pointing at the MAIN tree, so ALWAYS run
  pytest with `PYTHONPATH=src` semantics via the command below):
    `python3 -m pytest -q -p no:cacheprovider tests/<pkg>` with the
    worktree's src first on the path — use exactly:
    `/home/wporter/projects/pve-backup-validation/.venv/bin/python -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests/<pkg>`
    `/home/wporter/projects/pve-backup-validation/.venv/bin/ruff check src/pbv/<pkg> tests/<pkg>`
    `/home/wporter/projects/pve-backup-validation/.venv/bin/ruff format src/pbv/<pkg> tests/<pkg>`
  Verify that `python -c "import pbv.<pkg>; print(pbv.<pkg>.__file__)"`
  (with `-o pythonpath`/`PYTHONPATH=src`) points into YOUR worktree.
- Before finishing: ruff check clean, ruff format applied, your tests pass,
  and the frozen-contract tests still pass (`tests/test_config.py`).
- Commit on the current branch with a conventional commit message
  (`feat(<pkg>): ...`). Do not push, merge, or switch branches.
- Your process tree is memory-capped; keep test parallelism off.

Final answer: ONLY the JSON object required by the schema. In `tests_run`
give exact commands and their pass/fail counts. Separate verified facts from
assumptions. `acceptance_tests_covered` uses SPEC ids (A1..A17).
