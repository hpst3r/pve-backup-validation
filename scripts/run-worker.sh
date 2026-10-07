#!/usr/bin/env bash
# Launch one headless Claude (Opus) worker in its git worktree.
# Usage: run-worker.sh <name>
# Env: REPO_ROOT (main tree, required), WT_ROOT (worktree parent; default
#   $REPO_ROOT-wt), WT_DIR (explicit worktree/other repo path), WORKER_MODEL
#   (default opus), WORKER_TOOLS (allowedTools), WORKER_MEM (default 6G),
#   CLAUDE_GATE_ACCOUNT (LocalRouter claude account to admit-check; unset = no gate).
# Expects: $REPO_ROOT/docs/WORKER.md, docs/briefs/<name>.md, docs/worker-result.schema.json.
# Output: $REPO_ROOT/.runs/<name>/result.json (+ stderr.log). Exit 3 = reserve gate denied.
set -euo pipefail
name="$1"
root="${REPO_ROOT:?set REPO_ROOT}"
wt="${WT_DIR:-${WT_ROOT:-$root-wt}/$name}"
out="$root/.runs/$name"
mkdir -p "$out"

if [ -n "${CLAUDE_GATE_ACCOUNT:-}" ]; then
  rc=0; localrouter admit --class background --account "$CLAUDE_GATE_ACCOUNT" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 1 ]; then echo "claude reserve reached; not launching $name" >&2; exit 3; fi
fi

schema="$(cat "$root/docs/worker-result.schema.json")"
prompt="$(cat "$root/docs/WORKER.md")

Your assigned brief:

$(cat "$root/docs/briefs/$name.md")

Working directory is the worktree root ($wt). Your process tree is capped at ${WORKER_MEM:-6G} RAM; no parallel test runners; tests must finish in < 30 s."
cd "$wt"
# Exported here because env-prefixed commands are permission-blocked inside claude -p.
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$wt/src"
tools="${WORKER_TOOLS:-Read Edit Write Glob Grep Bash(/home/wporter/projects/pve-backup-validation/.venv/bin/python:*) Bash(/home/wporter/projects/pve-backup-validation/.venv/bin/ruff:*) Bash(python3:*) Bash(openssl:*) Bash(env:*) Bash(git add:*) Bash(git commit:*) Bash(git status:*) Bash(git diff:*) Bash(git log:*) Bash(git show:*) Bash(ls:*) Bash(mkdir:*) Bash(cat:*) Bash(chmod:*)}"
exec systemd-run --user --scope -q -p MemoryMax="${WORKER_MEM:-6G}" -p MemorySwapMax=0 \
  nice -n 10 claude -p "$prompt" \
  --model "${WORKER_MODEL:-opus}" \
  --permission-mode acceptEdits \
  --allowedTools "$tools" \
  --add-dir "$root" \
  --output-format json \
  --json-schema "$schema" \
  > "$out/result.json" 2> "$out/stderr.log"
