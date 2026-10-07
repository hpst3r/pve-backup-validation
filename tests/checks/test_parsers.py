"""Table-driven tests for output parsers and text helpers."""

from __future__ import annotations

import pytest

from pbv.checks._common import (
    DETAIL_MAX,
    http_accepted,
    judge_exit,
    one_line,
    parse_http_output,
    parse_listening,
    ps_quote,
    truncate_detail,
)
from pbv.checks._common import Kind
from pbv.checks.linux import count_log_matches
from pbv.checks.windows import parse_tcp_output

SS_H = """\
LISTEN 0      128          0.0.0.0:2222       0.0.0.0:*
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      128             [::]:22            [::]:*
LISTEN 0      511                *:8080             *:*
"""
SS_HEADER = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1,fd=3))
"""
NETSTAT_LINUX = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
"""
NETSTAT_WIN_DE = (
    "\r\nAktive Verbindungen\r\n\r\n  Proto  Lokale Adresse         Remoteadresse          Status\r\n"
    "  TCP    0.0.0.0:135            0.0.0.0:0              ABHÖREN\r\n"
    "  TCP    0.0.0.0:3389           0.0.0.0:0              ABHÖREN\r\n"
    "  TCP    10.99.0.5:49700        10.99.0.9:445          HERGESTELLT\r\n"
    "  TCP    [::]:445               [::]:0                 ABHÖREN\r\n"
    "  UDP    0.0.0.0:53             *:*                    \r\n"
)


@pytest.mark.parametrize(
    ("output", "port", "expected"),
    [
        (SS_H, 2222, True),
        (SS_H, 22, True),  # IPv6 [::]:22
        (SS_H, 222, False),  # no substring match on :2222
        (SS_H, 2, False),
        (SS_H, 53, True),  # 127.0.0.53%lo:53
        (SS_H, 8080, True),  # *:8080
        (SS_H, 80, False),
        (SS_HEADER, 22, True),
        (SS_HEADER, 0, False),
        (NETSTAT_LINUX, 3306, True),
        (NETSTAT_LINUX, 22, True),  # :::22
        (NETSTAT_LINUX, 330, False),
        (NETSTAT_WIN_DE, 3389, True),  # localized header/state columns
        (NETSTAT_WIN_DE, 445, True),  # [::]:445 listening; the established :445 peer must not count
        (NETSTAT_WIN_DE, 49700, False),  # established, not listening
        (NETSTAT_WIN_DE, 53, False),  # UDP ignored
        (NETSTAT_WIN_DE, 338, False),
        ("", 22, False),
        ("   \r\n  \n", 22, False),
        (SS_H.replace("\n", "\r\n") + "   ", 2222, True),  # CRLF + trailing whitespace
    ],
)
def test_parse_listening(output: str, port: int, expected: bool) -> None:
    assert parse_listening(output, port) is expected


@pytest.mark.parametrize(
    ("output", "port", "expected"),
    [
        ("PBV_COUNT 2\r\n", 3389, True),
        ("PBV_COUNT 0\r\n", 3389, False),
        ("PBV_NETSTAT\r\n" + NETSTAT_WIN_DE, 3389, True),
        ("PBV_NETSTAT\r\n" + NETSTAT_WIN_DE, 80, False),
        ("garbage", 80, None),
        ("", 80, None),
    ],
)
def test_parse_windows_tcp_output(output: str, port: int, expected: bool | None) -> None:
    assert parse_tcp_output(output, port) is expected


@pytest.mark.parametrize(
    ("stdout", "code", "err", "body"),
    [
        ("PBV_HTTP 200\n", 200, "", ""),
        ("PBV_HTTP 200\r\nPBV_BODY\r\n<html>ok</html>", 200, "", "<html>ok</html>"),
        ("PBV_HTTP 404\nPBV_BODY\nline1\nPBV_BODY in body\n", 404, "", "line1\nPBV_BODY in body\n"),
        ("PBV_HTTP 000\n", 0, "", ""),
        (
            "PBV_HTTP_ERR Unable to connect to the remote server\r\nPBV_HTTP 0\r\n",
            0,
            "Unable to connect to the remote server",
            "",
        ),
        ("", None, "", ""),
        ("PBV_HTTP \n", None, "", ""),
    ],
)
def test_parse_http_output(stdout: str, code: int | None, err: str, body: str) -> None:
    assert parse_http_output(stdout) == (code, err, body)


def test_parse_http_output_caps_body() -> None:
    _code, _err, body = parse_http_output("PBV_HTTP 200\nPBV_BODY\n" + "x" * 100_000)
    assert len(body) == 64 * 1024


@pytest.mark.parametrize(
    ("code", "expect", "ok"),
    [
        (200, None, True),
        (204, None, True),
        (301, None, True),
        (399, None, True),
        (401, None, True),
        (403, None, True),
        (404, None, False),
        (500, None, False),
        (199, None, False),
        (0, None, False),
        (404, [404], True),
        (200, [204], False),
        (200, [], True),  # empty list behaves like the default
    ],
)
def test_http_accepted(code: int, expect: list[int] | None, ok: bool) -> None:
    assert http_accepted(code, expect) is ok


@pytest.mark.parametrize(
    ("params", "code", "stdout", "kind"),
    [
        ({}, 0, "", Kind.PASS),
        ({}, 1, "", Kind.FAIL),
        ({"expect_exit": [0, 2]}, 2, "", Kind.PASS),
        ({"warn_exit": [3]}, 3, "", Kind.WARN),
        ({"stdout_regex": r"^OK$"}, 0, "foo\r\nOK\r\n".replace("\r", ""), Kind.FAIL),  # re.search without MULTILINE
        ({"stdout_regex": r"OK"}, 0, "all OK\n", Kind.PASS),
        ({"stdout_regex": r"OK"}, 0, "nope\n", Kind.FAIL),
        ({}, None, "", Kind.FAIL),
    ],
)
def test_judge_exit(params: dict, code: int | None, stdout: str, kind: Kind) -> None:
    assert judge_exit(params, code, stdout, what="x").kind is kind


def test_one_line_collapses_and_caps() -> None:
    assert one_line("a\r\nb\t c  ") == "a b c"
    long = one_line("x" * 500)
    assert len(long) == 200 and long.endswith("…")


def test_truncate_detail_keeps_tail() -> None:
    assert truncate_detail("short") == "short"
    text = "HEAD" + "y" * 20_000 + "TAIL"
    out = truncate_detail(text)
    assert len(out.encode()) <= DETAIL_MAX
    assert out.startswith("[…truncated ") and out.endswith("TAIL")
    assert "HEAD" not in out
    # multibyte characters never produce invalid UTF-8
    out2 = truncate_detail("é" * 10_000)
    assert len(out2.encode()) <= DETAIL_MAX
    out2.encode("utf-8")


@pytest.mark.parametrize(
    ("value", "quoted"),
    [
        ("plain", "'plain'"),
        ("it's", "'it''s'"),
        ("x'; Remove-Item C:\\ -Recurse; '", "'x''; Remove-Item C:\\ -Recurse; '''"),
        ("$env:SECRET `n $(calc)", "'$env:SECRET `n $(calc)'"),
        ("a\u2019b", "'a\u2019\u2019b'"),
        ("", "''"),
    ],
)
def test_ps_quote(value: str, quoted: str) -> None:
    assert ps_quote(value) == quoted


def test_count_log_matches() -> None:
    log = (
        "INF Starting tunnel\n"
        "ERR error dialing: dial tcp 1.1.1.1:7844: network is unreachable\n"
        "ERR Failed to fetch features: no such host\n"
        "ERR fatal: invalid credentials file\r\n"
        "INF errorless line\n"
    )
    from pbv.checks.discovery import CLOUDFLARED_ERROR_REGEX, CLOUDFLARED_IGNORE_REGEX

    hits = count_log_matches(log, CLOUDFLARED_ERROR_REGEX, CLOUDFLARED_IGNORE_REGEX)
    assert hits == ["ERR fatal: invalid credentials file", "INF errorless line"]
    word = count_log_matches(log, r"(?i)\b(error|fatal|failed)\b", "")
    assert len(word) == 3
