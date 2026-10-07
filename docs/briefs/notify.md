# Brief: `pbv.notify` — rendering, email, ntfy, JSON, Telegram

Implement SPEC §6 fully. Public API (re-export from `src/pbv/notify/__init__.py`):

```python
def build_notifiers(cfg: pbv.config.NotifyConfig, *, run_dir: Path | None = None,
                    smtp_factory=None, opener=None, sleep=time.sleep, stdout=sys.stdout) -> list[Notifier]: ...
def send_test(notifiers: Sequence[Notifier], *, node: str = "test") -> dict[str, str]: ...
def should_send(when: NotifyWhen, status: Status, *, interrupted: bool = False, cleanup_failed: bool = False) -> bool: ...
def render_subject(report: RunReport, prefix: str = "[pbv]") -> str: ...
def render_text(report: RunReport, *, max_chars: int | None = None) -> str: ...
def render_vm_text(vm: VmResult, report: RunReport) -> str: ...
class EmailNotifier, NtfyNotifier, JsonNotifier, TelegramNotifier  # each implements pbv.core.Notifier
```

Details:
- Each notifier's `vm_finished`/`run_finished` performs its own `when`/`per_vm` gating (the orchestrator calls all
  of them unconditionally) and wraps any exception into `PbvError(code="NOTIFY_FAIL")` with a message like
  `"ntfy: HTTP 403 Forbidden"` or `"email: SMTPAuthenticationError (535)"` — never including the password/token,
  the full URL with credentials, or the response body beyond 200 chars.
- Rendering: deterministic, plain text; problems first. Subject: `"{prefix} {STATUS} {n_bad}/{n} VMs on {node} ({counts})"`
  e.g. `[pbv] FAIL 1/4 VMs on restore01 (3 pass, 1 fail)`; when all pass `[pbv] PASS 4/4 VMs on restore01`;
  interrupted → `INTERRUPTED`; any cleanup failure → prefix the status with `CLEANUP-FAILED `. Body: header
  (run_id, node, start/end, duration), `MANUAL CLEANUP REQUIRED: VM <temp> (from <vmid> <name>) on <node>` lines,
  then per-VM blocks sorted by severity desc then vmid, showing backup volid + age (h) + size (GiB 1 decimal),
  failure_code/message, each non-pass check `  ✗ name — summary` (✓ for pass, ! warn, - skipped), sanitize note count,
  screenshots count, log file; then notify_errors / leftovers swept. `max_chars` truncates with
  "\n…(truncated, see JSON report)".
- Email: `email.message.EmailMessage`, From/To/Subject/Date/Message-ID headers; STARTTLS with
  `ssl.create_default_context()`; `security="ssl"` uses SMTP_SSL; login only if username; attachments PNG ≤ 5 files
  and ≤ 10 MiB total (skip extras, mention in body); `smtp_factory(host, port, timeout)` injectable (default
  smtplib.SMTP / SMTP_SSL). Tests: a fake SMTP class recording starttls/login/send_message calls + a real
  loopback test with a tiny `socketserver`-based SMTP sink if simple (optional; aiosmtpd is NOT available).
- ntfy: `urllib.request.Request` POST to `{server}/{topic}`; headers Title (subject; non-ASCII → RFC 2047 or use
  the `X-Title` with UTF-8? ntfy accepts UTF-8 header values encoded as `=?UTF-8?B?...?=` — implement that for
  non-ASCII), Priority, Tags (comma list), Markdown: yes only if you render markdown (plain text: omit),
  Click if set, Authorization Bearer if token; body UTF-8 ≤ 4096 bytes (truncate with note). Attachments: PUT with
  `Filename` header + `Title`, at most 3 PNGs. Retry 429/5xx twice with injected sleep (1 s, 3 s); 4xx other → fail
  immediately. `opener` injectable (callable(Request, timeout) -> response). Test against a loopback
  `http.server` recording requests.
- JSON: per SPEC; `os.replace` atomic writes, mode 0o640, dir created (0o750); partial file per vm_finished;
  run_finished writes final + latest (copy, not symlink) and removes partial; retention deletes oldest
  `<run_id>.json` beyond `keep` (sorted by name — run_ids sort chronologically), never latest.json, never *.partial.json
  of other runs younger than 1 day. `stdout=True` prints the JSON (indent 2) to the injected stream. `when` applies
  (default always). JSON uses `pbv.core.report_to_dict` + `json.dumps(..., indent=2, sort_keys=True, ensure_ascii=False)`.
- Telegram: POST form to `https://api.telegram.org/bot<token>/sendMessage` (chat_id, text ≤ 4096, message_thread_id
  if set, disable_notification for pass). The URL contains the token — make sure error messages say "telegram: HTTP n"
  without the URL. Base URL injectable for tests.
- `send_test`: builds a synthetic RunReport (one PASS VM), calls `run_finished` on each notifier with gating
  bypassed (add an internal `force=True` path or temporarily construct with when=ALWAYS), returns {name: "ok"|error}.

Tests in `tests/notify/` cover A15 completely: should_send truth table; render snapshot asserts for pass/fail/
cleanup-failed/interrupted reports (build reports by hand from pbv.core dataclasses); email (fake SMTP) with
starttls/ssl/none, login, attachments limit; ntfy against a loopback HTTP server (headers, auth, truncation,
429 retry, 403 no-retry, non-ASCII title); JSON (atomic write, perms, latest, partial lifecycle, retention, stdout);
Telegram via loopback server; secrets never in raised messages (sentinel token).
