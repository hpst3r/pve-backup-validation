"""Windows guest checks: PowerShell command builders (pure) and evaluators.

Every script runs as ``powershell.exe -NoProfile -NonInteractive
-ExecutionPolicy Bypass -Command <script>``. Interpolated strings are
PowerShell single-quoted literals (:func:`ps_quote`), ints are formatted from
Python ints, and the scripts contain no double quotes (they would need extra
escaping on the Windows command line the guest agent builds).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pbv.checks._common import (
    OUTPUT_CAP,
    Attempt,
    Kind,
    Outcome,
    evaluate_http,
    http_url,
    lines,
    output_detail,
    parse_listening,
    ps_argv,
    ps_quote,
)

# ── builders ───────────────────────────────────────────────────────────────────


def service_status_argv(name: str) -> list[str]:
    """Print the service's ``Status`` (``Running``…) or ``PBV_NOSERVICE``.

    The name is wildcard-escaped so ``Get-Service`` matches it literally.
    """
    q = ps_quote(name)
    script = (
        "try { $s = @(Get-Service -ErrorAction Stop -Name "
        f"([System.Management.Automation.WildcardPattern]::Escape({q}))); "
        "if ($s.Count -eq 0) { 'PBV_NOSERVICE' } else { [string]$s[0].Status } } "
        "catch { 'PBV_NOSERVICE' }"
    )
    return ps_argv(script)


def tcp_listen_argv(port: int) -> list[str]:
    """``Get-NetTCPConnection -State Listen -LocalPort <p>`` count, else ``netstat -an``."""
    p = int(port)
    script = (
        "if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) { "
        f"$c = @(Get-NetTCPConnection -State Listen -LocalPort {p} -ErrorAction SilentlyContinue); "
        "'PBV_COUNT ' + $c.Count } "
        "else { 'PBV_NETSTAT'; netstat -an }"
    )
    return ps_argv(script)


def http_argv(params: Mapping[str, Any], timeout_s: float) -> list[str]:
    """``Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0`` printing ``PBV_HTTP <code>``.

    Certificate checks are disabled with ``-SkipCertificateCheck`` on PS ≥ 6
    and a ServicePointManager callback on 5.1. 3xx/4xx/5xx statuses are read
    from the error's ``Response`` when PowerShell reports them as errors.
    """
    url = ps_quote(http_url(params))
    t = max(1, int(timeout_s))
    want_body = bool(params.get("body_regex"))
    body = (
        "if ($body.Length -gt " + str(OUTPUT_CAP) + ") { $body = $body.Substring(0, " + str(OUTPUT_CAP) + ") }; "
        "'PBV_BODY'; $body"
        if want_body
        else ""
    )
    script = (
        "$ProgressPreference = 'SilentlyContinue'; "
        f"$p = @{{ Uri = {url}; UseBasicParsing = $true; MaximumRedirection = 0; TimeoutSec = {t} }}; "
        "if ($PSVersionTable.PSVersion.Major -ge 6) { $p['SkipCertificateCheck'] = $true; "
        "$p['SkipHttpErrorCheck'] = $true } "
        "else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; "
        "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls11,Tls' }; "
        "$code = 0; $body = ''; $r = $null; $ev = $null; "
        "try { $r = Invoke-WebRequest @p -ErrorAction SilentlyContinue -ErrorVariable ev } catch { $ev = @($_) }; "
        "if ($r -ne $null) { $code = [int]$r.StatusCode; $body = [string]$r.Content } "
        "elseif ($ev) { $e = $ev[0].Exception; "
        "if ($e.Response -ne $null) { $code = [int]$e.Response.StatusCode } "
        "else { 'PBV_HTTP_ERR ' + ($e.Message -replace '[\\r\\n]+', ' ') } }; "
        "'PBV_HTTP ' + $code; "
        f"{body}"
    )
    return ps_argv(script.rstrip("; ").rstrip())


def remove_file_argv(path: str) -> list[str]:
    return ps_argv(f"Remove-Item -LiteralPath {ps_quote(path)} -Force -ErrorAction SilentlyContinue")


# ── parsers / evaluators ───────────────────────────────────────────────────────


def parse_tcp_output(stdout: str, port: int) -> bool | None:
    """True/False if determinable; None if the output is unrecognized."""
    ls = lines(stdout)
    for ln in ls:
        if ln.startswith("PBV_COUNT"):
            val = ln[len("PBV_COUNT") :].strip()
            return val.isdigit() and int(val) > 0
    if ls and ls[0] == "PBV_NETSTAT":
        return parse_listening("\n".join(ls[1:]), port)
    return None


def check_service(att: Attempt) -> Outcome:
    name = str(att.spec.params["service"])
    res = att.exec(service_status_argv(name))
    out = lines(res.stdout)
    status = out[-1] if out else ""
    if status == "Running":
        return Outcome(Kind.PASS, f"{name} is Running")
    if status == "PBV_NOSERVICE":
        return Outcome(Kind.FAIL, f"service {name} not found", output_detail(res))
    return Outcome(Kind.FAIL, f"{name} is {status or 'unknown'}", output_detail(res))


def check_tcp_listen(att: Attempt, port: int | None = None) -> Outcome:
    port = int(att.spec.params["port"] if port is None else port)
    res = att.exec(tcp_listen_argv(port))
    found = parse_tcp_output(res.stdout, port)
    if found:
        return Outcome(Kind.PASS, f"TCP port {port} is listening")
    if found is None:
        return Outcome(Kind.FAIL, f"cannot check port {port}: unexpected output", output_detail(res))
    return Outcome(Kind.FAIL, f"no TCP listener on port {port}", output_detail(res))


def check_http(att: Attempt) -> Outcome:
    p = att.spec.params
    res = att.exec(http_argv(p, att.remaining()))
    return evaluate_http(p, http_url(p), res.stdout, output_detail(res))
