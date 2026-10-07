"""Linux guest checks: command builders (pure, return argv) and evaluators.

Commands that need no shell are plain argv lists. Where a shell pipeline is
needed (``tcp_listen`` fallback, ``http``), the script is fixed text and every
interpolated value is :func:`shlex.quote`-d; ports and timeouts are ints.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from typing import Any

from pbv.checks._common import (
    OUTPUT_CAP,
    Attempt,
    Kind,
    Outcome,
    evaluate_http,
    http_url,
    output_detail,
    parse_listening,
    sh_argv,
)

# ── builders ───────────────────────────────────────────────────────────────────


def systemd_active_argv(unit: str) -> list[str]:
    return ["systemctl", "is-active", "--", unit]


def systemd_show_argv(unit: str) -> list[str]:
    return ["systemctl", "show", "-p", "ActiveState,SubState,Result", "--", unit]


def journal_tail_argv(unit: str, n: int = 15) -> list[str]:
    return ["journalctl", "--unit", unit, "-n", str(int(n)), "--no-pager"]


def log_scan_argv(unit: str, since: str) -> list[str]:
    return ["journalctl", "--unit", unit, "--since", since, "--no-pager", "-o", "cat"]


TCP_LISTEN_SCRIPT = (
    "if command -v ss >/dev/null 2>&1; then echo PBV_TOOL ss; ss -ltn; "
    "elif command -v netstat >/dev/null 2>&1; then echo PBV_TOOL netstat; netstat -ltn; "
    "else echo PBV_NOTOOL; fi"
)


def tcp_listen_argv() -> list[str]:
    """``ss -ltn`` (fallback ``netstat -ltn``); the port is matched in Python."""
    return sh_argv(TCP_LISTEN_SCRIPT)


def http_argv(params: Mapping[str, Any], timeout_s: float) -> list[str]:
    """One shell script printing ``PBV_HTTP <code>`` (and the capped body after ``PBV_BODY``).

    curl first, then wget; neither → ``PBV_NOCLIENT``.
    """
    url = shlex.quote(http_url(params))
    t = max(1, int(timeout_s))
    want_body = bool(params.get("body_regex"))
    body = f'echo PBV_BODY; head -c {OUTPUT_CAP} "$t"; ' if want_body else ""
    script = (
        f"u={url}; "
        "t=$(mktemp 2>/dev/null || echo /tmp/pbv-http-$$); "
        "if command -v curl >/dev/null 2>&1; then "
        f'c=$(curl -skg --max-time {t} -o "$t" -w \'%{{http_code}}\' "$u" 2>/dev/null); '
        "elif command -v wget >/dev/null 2>&1; then "
        f'c=$(wget --no-check-certificate -T {t} -S -O "$t" "$u" 2>&1 | '
        "awk '$1 ~ /^HTTP\\// {print $2}' | tail -n 1); "
        'else echo PBV_NOCLIENT; rm -f "$t"; exit 0; fi; '
        'echo "PBV_HTTP ${c:-000}"; '
        f"{body}"
        'rm -f "$t"'
    )
    return sh_argv(script)


def count_log_matches(text: str, error_regex: str, ignore_regex: str) -> list[str]:
    err = re.compile(error_regex)
    ign = re.compile(ignore_regex) if ignore_regex else None
    out = []
    for ln in text.splitlines():
        if err.search(ln) and not (ign and ign.search(ln)):
            out.append(ln.rstrip())
    return out


# ── evaluators ─────────────────────────────────────────────────────────────────


def check_systemd(att: Attempt) -> Outcome:
    unit = str(att.spec.params["unit"])
    res = att.exec(systemd_active_argv(unit))
    state = res.stdout.strip().splitlines()[0].strip() if res.stdout.strip() else ""
    if state == "active":
        return Outcome(Kind.PASS, f"{unit} is active")
    show = att.try_exec(systemd_show_argv(unit))
    props = " ".join(show.stdout.split()) if show is not None else ""
    journal = att.try_exec(journal_tail_argv(unit))
    detail = output_detail(res, header=f"systemctl is-active {unit}")
    if props:
        detail += f"\n--- systemctl show ---\n{props}"
    if journal is not None and journal.stdout.strip():
        detail += f"\n--- journalctl -u {unit} -n 15 ---\n{journal.stdout.rstrip()}"
    summary = f"{unit} is {state or 'unknown'}" + (f" ({props})" if props else "")
    return Outcome(Kind.FAIL, summary, detail)


def check_tcp_listen(att: Attempt, port: int | None = None) -> Outcome:
    port = int(att.spec.params["port"] if port is None else port)
    res = att.exec(tcp_listen_argv())
    if "PBV_NOTOOL" in res.stdout:
        return Outcome(Kind.FAIL, f"cannot check port {port}: neither ss nor netstat in guest", output_detail(res))
    if parse_listening(res.stdout, port):
        return Outcome(Kind.PASS, f"TCP port {port} is listening")
    return Outcome(Kind.FAIL, f"no TCP listener on port {port}", output_detail(res))


def check_http(att: Attempt) -> Outcome:
    p = att.spec.params
    url = http_url(p)
    res = att.exec(http_argv(p, att.remaining()))
    if "PBV_NOCLIENT" in res.stdout:
        tcp = check_tcp_listen(att, int(p["port"]))
        if tcp.kind is Kind.PASS:
            return Outcome(Kind.WARN, f"no HTTP client in guest; port {p['port']} listening")
        return Outcome(Kind.FAIL, f"no HTTP client in guest; {tcp.summary}", tcp.detail)
    return evaluate_http(p, url, res.stdout, output_detail(res))


def check_log_scan(att: Attempt) -> Outcome:
    p = att.spec.params
    unit = str(p["unit"])
    since = str(p.get("since") or "5 min ago")
    res = att.exec(log_scan_argv(unit, since))
    if res.exitcode != 0:
        return Outcome(Kind.FAIL, f"journalctl for {unit} failed (exit {res.exitcode})", output_detail(res))
    error_regex = p.get("error_regex") or r"(?i)\b(error|fatal|failed)\b"
    matches = count_log_matches(res.stdout, error_regex, p.get("ignore_regex") or "")
    limit = int(p.get("max_matches") or 0)
    summary = f"{unit}: {len(matches)} error line(s) since '{since}' (max {limit})"
    detail = "\n".join(matches[-50:])
    return Outcome(Kind.PASS if len(matches) <= limit else Kind.FAIL, summary, detail)
