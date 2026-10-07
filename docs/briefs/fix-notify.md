# Brief (fix wave): `pbv.notify` — review findings

You own `src/pbv/notify/`, `tests/notify/`, and `tests/review/test_notify_review.py`. `pbv.core.RunReport` gained
`sweep_failures: list[str]` ("<temp vmid>: <code> <message>").

Review gating: tests under `tests/review/` call `review_bug("...")`, which skips unless `PBV_REVIEW=1`. For each finding
you fix, DELETE that `review_bug(...)` line in the matching review test (you may edit only the review tests for your
findings) and make it pass without weakening its assertions; add regression tests in your own `tests/<pkg>/`.
Verify with `PBV_REVIEW=1 .../python -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests/review/<file>`
(exporting is blocked; use `env PBV_REVIEW=1 ...`). Then run the WHOLE suite
(`... -m pytest -q -p no:cacheprovider --rootdir . -o pythonpath=src tests`), which must pass apart from review
tests owned by other fix workers, which stay skipped by default. Ruff check and format must be clean.

Fix:
1. [high] render_text / render_subject: sweep_failures render as `MANUAL CLEANUP REQUIRED: VM <id> on <node>
   (startup sweep: <code> <message>)` at the top, the subject gets the `CLEANUP-FAILED` label, and should_send's
   cleanup_failed must be true when sweep_failures is non-empty, so callers pass that through
   (test_render_text_reports_sweep_failures). Check every notifier's gating.
2. [medium] Never follow redirects for POST/PUT (ntfy, Telegram): use an opener whose redirect handler raises for
   non-GET methods. Treat any non-2xx final status as NOTIFY_FAIL ("ntfy: HTTP 301 redirect refused; check server
   URL") (test_ntfy_redirect_does_not_silently_drop_message).
3. [low] Retry only (a) failures before the request was sent (connection refused / DNS EAI_AGAIN) and (b) HTTP
   429/5xx responses. Never retry read timeouts or resets after sending (avoids duplicate notifications). Add tests.
4. [low] Telegram 4096 limit: measure UTF-16 code units (`len(text.encode("utf-16-le")) // 2`) and truncate safely
   without splitting surrogate pairs. Add a test with emoji.
