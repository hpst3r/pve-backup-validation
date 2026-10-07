"""Command builders: exact argv shape, quoting and shell-injection inertness.

The Linux shell scripts are also executed with a real ``/bin/sh`` against stub
``curl``/``wget``/``ss`` binaries to prove they behave and that hostile values
stay inert.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from pbv.checks import linux, scripts, windows
from pbv.checks._common import POWERSHELL, ps_quote
from pbv.core import OsFamily

EVIL_SH = "x; touch /tmp/pwned"
EVIL_PS = "x'; Remove-Item C:\\ -Recurse; '"


def _ps_script(argv: list[str]) -> str:
    assert argv[: len(POWERSHELL)] == list(POWERSHELL)
    assert argv[len(POWERSHELL)] == "-Command"
    assert len(argv) == len(POWERSHELL) + 2
    return argv[-1]


def _ps_tokens_outside_quotes(script: str) -> str:
    """The script with every single-quoted literal removed (``''`` escapes honoured)."""
    out, i, inq = [], 0, False
    while i < len(script):
        ch = script[i]
        if inq:
            if ch == "'" and script[i + 1 : i + 2] == "'":
                i += 2
                continue
            if ch == "'":
                inq = False
        elif ch == "'":
            inq = True
        else:
            out.append(ch)
        i += 1
    assert not inq, "unterminated quote"
    return "".join(out)


# ── Linux ──────────────────────────────────────────────────────────────────────


def test_systemd_argv_is_plain_argv_with_injection_as_one_token() -> None:
    assert linux.systemd_active_argv(EVIL_SH) == ["systemctl", "is-active", "--", EVIL_SH]
    assert linux.systemd_show_argv("-H evil")[-2:] == ["--", "-H evil"]
    assert linux.journal_tail_argv(EVIL_SH) == ["journalctl", "--unit", EVIL_SH, "-n", "15", "--no-pager"]
    assert linux.log_scan_argv("u", "5 min ago") == [
        "journalctl",
        "--unit",
        "u",
        "--since",
        "5 min ago",
        "--no-pager",
        "-o",
        "cat",
    ]


def test_tcp_listen_argv_has_no_interpolation() -> None:
    argv = linux.tcp_listen_argv()
    assert argv[:2] == ["/bin/sh", "-c"] and len(argv) == 3
    assert "ss -ltn" in argv[2] and "netstat -ltn" in argv[2]


def test_http_url_variants() -> None:
    from pbv.checks._common import http_url

    assert http_url({"port": 80}) == "http://127.0.0.1:80/"
    assert http_url({"port": 443, "scheme": "https", "host": "::1", "path": "/x?y=1"}) == "https://[::1]:443/x?y=1"


def test_http_argv_quotes_url() -> None:
    argv = linux.http_argv({"port": 80, "path": "/'; touch /tmp/pwned; '", "host": "127.0.0.1"}, 10)
    script = argv[2]
    url = "http://127.0.0.1:80/'; touch /tmp/pwned; '"
    assert f"u={shlex.quote(url)};" in script
    assert "--max-time 10" in script and "-T 10" in script
    assert "PBV_BODY" not in script  # no body_regex → body not printed
    body = linux.http_argv({"port": 80, "body_regex": "ok"}, 5)[2]
    assert "echo PBV_BODY; head -c 65536" in body


def _stub_bin(tmp_path: Path, tools: dict[str, str]) -> Path:
    """A PATH dir with the given stub scripts plus symlinks to the coreutils the scripts need."""
    d = tmp_path / "bin"
    d.mkdir()
    for name in ("mktemp", "head", "rm", "awk", "tail", "cat", "touch"):
        real = shutil.which(name)
        if real:
            (d / name).symlink_to(real)
    for name, body in tools.items():
        p = d / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)
    return d


def _run_sh(argv: list[str], path: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    assert argv[0] == "/bin/sh"
    return subprocess.run(
        argv, env={"PATH": str(path)}, cwd=cwd, capture_output=True, text=True, timeout=10, check=False
    )


CURL_STUB = """\
# record argv, write a body to -o, print the code via -w
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; last="$a"; done
printf '%s\\n' "$@" > "$PBV_ARGS_FILE"
printf 'hello pbv body' > "$out"
printf '%s' "${STUB_CODE:-200}"
"""

WGET_STUB = """\
out=""; prev=""
for a in "$@"; do [ "$prev" = "-O" ] && out="$a"; prev="$a"; done
printf '%s\\n' "$@" > "$PBV_ARGS_FILE"
printf 'wget body' > "$out"
echo "  HTTP/1.1 302 Found" >&2
echo "  HTTP/1.1 200 OK" >&2
exit 0
"""


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh")
def test_http_script_with_curl_and_injection_is_inert(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    args_file = tmp_path / "args"
    bindir = _stub_bin(tmp_path, {"curl": CURL_STUB.replace("$PBV_ARGS_FILE", str(args_file))})
    evil_path = f"/'; touch {marker}; echo '$(touch {marker})`touch {marker}`"
    argv = linux.http_argv({"port": 8080, "path": evil_path, "body_regex": "pbv"}, 7)
    cp = _run_sh(argv, bindir, tmp_path)
    assert cp.returncode == 0, cp.stderr
    assert not marker.exists()
    assert "PBV_HTTP 200" in cp.stdout
    assert cp.stdout.split("PBV_BODY\n", 1)[1] == "hello pbv body"
    recorded = args_file.read_text().splitlines()
    assert recorded[-1] == f"http://127.0.0.1:8080{evil_path}"  # URL arrived as ONE argument, verbatim
    assert "--max-time" in recorded and "7" in recorded


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh")
def test_http_script_wget_fallback_takes_last_status(tmp_path: Path) -> None:
    args_file = tmp_path / "args"
    bindir = _stub_bin(tmp_path, {"wget": WGET_STUB.replace("$PBV_ARGS_FILE", str(args_file))})
    cp = _run_sh(linux.http_argv({"port": 80, "body_regex": "x"}, 3), bindir, tmp_path)
    assert "PBV_HTTP 200" in cp.stdout
    assert cp.stdout.endswith("PBV_BODY\nwget body")


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh")
def test_http_script_without_client_prints_noclient(tmp_path: Path) -> None:
    bindir = _stub_bin(tmp_path, {})
    cp = _run_sh(linux.http_argv({"port": 80}, 3), bindir, tmp_path)
    assert cp.stdout.strip() == "PBV_NOCLIENT"


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh")
@pytest.mark.parametrize(
    ("tools", "expect"),
    [
        ({"ss": "echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'\n"}, "PBV_TOOL ss"),
        ({"netstat": "echo 'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN'\n"}, "PBV_TOOL netstat"),
        ({}, "PBV_NOTOOL"),
    ],
)
def test_tcp_listen_script_tool_fallback(tmp_path: Path, tools: dict[str, str], expect: str) -> None:
    cp = _run_sh(linux.tcp_listen_argv(), _stub_bin(tmp_path, tools), tmp_path)
    assert cp.stdout.splitlines()[0] == expect


def test_linux_script_argv_env_and_interpreter() -> None:
    env = {"PBV_RUN_ID": "r1", "EVIL": EVIL_SH}
    argv = scripts.linux_script_argv("/tmp/pbv-r1-1-check.sh", "", ["a b", EVIL_SH], env)
    assert argv == [
        "/usr/bin/env",
        "PBV_RUN_ID=r1",
        f"EVIL={EVIL_SH}",
        "/bin/sh",
        "/tmp/pbv-r1-1-check.sh",
        "a b",
        EVIL_SH,
    ]
    custom = scripts.linux_script_argv("/tmp/s.py", "/usr/bin/python3 -u", [], {})
    assert custom == ["/usr/bin/env", "/usr/bin/python3", "-u", "/tmp/s.py"]


def test_guest_script_paths() -> None:
    rid = "20261007T020000Z-ab12"
    assert scripts.guest_script_path(OsFamily.LINUX, rid, 3, "check db.sh") == f"/tmp/pbv-{rid}-3-check_db.sh"
    assert scripts.guest_script_path(OsFamily.LINUX, rid, 1, "../../etc/passwd") == f"/tmp/pbv-{rid}-1-etc_passwd"
    assert scripts.guest_script_path(OsFamily.WINDOWS, rid, 2, "c.ps1") == f"C:\\Windows\\Temp\\pbv-{rid}-2-c.ps1"
    assert scripts.guest_script_path(OsFamily.WINDOWS, rid, 2, "c.CMD").endswith("-2-c.CMD")
    assert scripts.guest_script_path(OsFamily.WINDOWS, rid, 2, "c.sh").endswith("-2-c.sh.ps1")
    assert scripts.guest_script_path(OsFamily.WINDOWS, rid, 2, "c.py", "python.exe").endswith("-2-c.py")


def test_cleanup_argv() -> None:
    assert scripts.cleanup_argv(OsFamily.LINUX, "/tmp/x") == ["rm", "-f", "--", "/tmp/x"]
    s = _ps_script(scripts.cleanup_argv(OsFamily.WINDOWS, "C:\\Windows\\Temp\\it's.ps1"))
    assert s == "Remove-Item -LiteralPath 'C:\\Windows\\Temp\\it''s.ps1' -Force -ErrorAction SilentlyContinue"


# ── Windows ────────────────────────────────────────────────────────────────────


def test_windows_service_argv_injection_inert() -> None:
    script = _ps_script(windows.service_status_argv(EVIL_PS))
    assert ps_quote(EVIL_PS) in script
    outside = _ps_tokens_outside_quotes(script)
    assert "Remove-Item" not in outside
    assert '"' not in script


def test_windows_tcp_argv() -> None:
    script = _ps_script(windows.tcp_listen_argv(3389))
    assert "Get-NetTCPConnection -State Listen -LocalPort 3389" in script
    assert "netstat -an" in script
    assert '"' not in script


def test_windows_http_argv_injection_inert_and_shape() -> None:
    params = {"port": 443, "scheme": "https", "path": "/" + EVIL_PS, "host": "127.0.0.1", "body_regex": "ok"}
    script = _ps_script(windows.http_argv(params, 12))
    assert "Uri = 'https://127.0.0.1:443/x''; Remove-Item C:\\ -Recurse; '''" in script
    assert "Remove-Item" not in _ps_tokens_outside_quotes(script)
    for needle in (
        "UseBasicParsing = $true",
        "MaximumRedirection = 0",
        "TimeoutSec = 12",
        "SkipCertificateCheck",
        "ServerCertificateValidationCallback",
        "$e.Response.StatusCode",
        "'PBV_HTTP ' + $code",
        "'PBV_BODY'; $body",
    ):
        assert needle in script, needle
    assert '"' not in script
    assert "PBV_BODY" not in _ps_script(windows.http_argv({"port": 80}, 5))


WRAP_TAIL = " } catch { Write-Output $_.Exception.Message; exit 1 }; if ($null -eq $LASTEXITCODE) { exit 1 }; exit $LASTEXITCODE"


def test_windows_script_argv_variants() -> None:
    env = {"PBV_RUN_ID": "r", "EVIL": EVIL_PS}
    dest = "C:\\Windows\\Temp\\pbv-r-1-c.ps1"
    s = _ps_script(scripts.windows_script_argv(dest, "", ["a b", EVIL_PS], env))
    assert s.startswith("$env:PBV_RUN_ID = 'r'; $env:EVIL = 'x''; Remove-Item C:\\ -Recurse; '''; ")
    assert (
        "try { & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "
        "'C:\\Windows\\Temp\\pbv-r-1-c.ps1' 'a b' 'x''; Remove-Item C:\\ -Recurse; '''" + WRAP_TAIL
    ) in s
    assert "Remove-Item" not in _ps_tokens_outside_quotes(s)
    cmd = _ps_script(scripts.windows_script_argv("C:\\T\\x.cmd", "", [], {}))
    assert cmd == "try { & cmd.exe /c 'C:\\T\\x.cmd'" + WRAP_TAIL
    bat = _ps_script(scripts.windows_script_argv("C:\\T\\x.BAT", "", ["1"], {}))
    assert bat == "try { & cmd.exe /c 'C:\\T\\x.BAT' '1'" + WRAP_TAIL
    custom = _ps_script(
        scripts.windows_script_argv("C:\\T\\x.py", '"C:\\Program Files\\Python\\python.exe" -u', [], {})
    )
    assert custom == "try { & 'C:\\Program Files\\Python\\python.exe' '-u' 'C:\\T\\x.py'" + WRAP_TAIL


def test_windows_cmd_script_args_are_double_quoted_for_cmd() -> None:
    s = _ps_script(scripts.windows_script_argv("C:\\T\\x.cmd", "", ["a b", "plain", "", "tab\there"], {}))
    assert s == "try { & cmd.exe /c 'C:\\T\\x.cmd' '\"a b\"' 'plain' '\"\"' '\"tab\there\"'" + WRAP_TAIL
    # Only cmd.exe gets the extra double quotes; PowerShell/other interpreters do not.
    ps = _ps_script(scripts.windows_script_argv("C:\\T\\x.ps1", "", ["a b"], {}))
    assert "'a b'" in ps and '"' not in ps
    py = _ps_script(scripts.windows_script_argv("C:\\T\\x.cmd", "python.exe", ["a b"], {}))
    assert "'a b'" in py and '"a b"' not in py


def test_no_double_quotes_in_windows_discovery() -> None:
    from pbv.checks.discovery import WINDOWS_LIST_ARGV

    script = _ps_script(list(WINDOWS_LIST_ARGV))
    assert "Get-CimInstance -ClassName Win32_Service -Filter 'StartMode=''Auto'''" in script
    assert "StartType -eq 'Automatic'" in script
    assert '"' not in script
