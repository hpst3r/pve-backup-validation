#!/usr/bin/env bash
# Full verification gate. Exits non-zero on any failure; run before every commit.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
"$PY" -m compileall -q src
"$PY" -m pytest -q -p no:cacheprovider
PBV_REVIEW=1 "$PY" -m pytest -q -p no:cacheprovider tests/review
left=$({ grep -rnE '^[[:space:]]+review_bug\(' tests/review --include='test_*.py' || true; } | wc -l)
[ "$left" -eq 0 ] || { echo "open review findings: $left" >&2; exit 1; }
bash -n deploy/setup-restore-node.sh
echo "GATE OK"
