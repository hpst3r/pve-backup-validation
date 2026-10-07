"""A14: PveClient against a TLS loopback server."""

from __future__ import annotations

import base64
import logging

import pytest

from pbv.config import TargetConfig
from pbv.core import ApiError, GuestAgentError, PbvTimeoutError, PveApi
from pbv.pve import PveClient, api_path, normalize_fingerprint
from pbv.pve.client import FILE_WRITE_MAX_BYTES, _maybe_b64

from .conftest import DROP, SECRET, TOKEN_ID, FakeClock, Reply, Server

UPID = "UPID:restore01:00001234:00005678:65000000:qmrestore:900105:pbv@pve!validate:"
Q = "/nodes/restore01/qemu"


def data(d: object) -> dict[str, object]:
    return {"data": d}


# ── basics: protocol, auth, encoding, quoting ─────────────────────────────────


def test_implements_protocol(srv: Server) -> None:
    assert isinstance(srv.client(), PveApi)


def test_auth_header_and_version(srv: Server) -> None:
    srv.route("GET", "/version", data({"version": "9.0.10", "release": "9.0"}))
    assert srv.client().version()["version"] == "9.0.10"
    (req,) = srv.requests
    assert req.headers["Authorization"] == f"PVEAPIToken={TOKEN_ID}={SECRET}"
    assert req.raw_path == "/api2/json/version"


def test_form_encoding_list_repetition_and_booleans(srv: Server) -> None:
    srv.route("POST", f"{Q}/900105/agent/exec", data({"pid": 4242}))
    pid = srv.client().agent_exec(900105, ["sh", "-c", "echo a&b=c"], input_data=b"hello\n")
    assert pid == 4242
    (req,) = srv.requests
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert req.form["command"] == ["sh", "-c", "echo a&b=c"]
    assert req.form["input-data"] == ["hello\n"]
    assert req.body.startswith(b"command=sh&command=-c&command=echo+a%26b%3Dc")


def test_restore_params(srv: Server) -> None:
    srv.route("POST", Q, data(UPID))
    c = srv.client()
    volid = "pbs:backup/vm/105/2026-10-01T02:00:00Z"
    assert c.restore_vm(900105, volid, "local-lvm") == UPID
    assert c.restore_vm(900105, volid, "local-lvm", pool="pbv", bwlimit_kib=51200, unique=False) == UPID
    first, second = srv.requests
    assert first.form == {"vmid": ["900105"], "archive": [volid], "storage": ["local-lvm"], "unique": ["1"]}
    assert second.form["unique"] == ["0"]
    assert second.form["pool"] == ["pbv"]
    assert second.form["bwlimit"] == ["51200"]


def test_path_segments_are_quoted() -> None:
    volid = "pbs:backup/vm/105/2026-10-01T02:00:00Z"
    assert api_path("nodes", "n1", "storage", "pbs", "content", volid) == (
        "/nodes/n1/storage/pbs/content/pbs%3Abackup%2Fvm%2F105%2F2026-10-01T02%3A00%3A00Z"
    )


def test_volid_like_segment_quoted_on_the_wire(srv: Server) -> None:
    srv.route("DELETE", "/nodes/restore01/tasks/.*", data(None))
    srv.client().stop_task("pbs:backup/vm/105/x y")
    (req,) = srv.requests
    assert req.raw_path == "/api2/json/nodes/restore01/tasks/pbs%3Abackup%2Fvm%2F105%2Fx%20y"


def test_upid_quoted_in_task_status_path(srv: Server) -> None:
    srv.route("GET", "/nodes/restore01/tasks/[^/]+/status", data({"status": "stopped", "exitstatus": "OK"}))
    srv.client().wait_task(UPID, 10)
    assert srv.requests[0].raw_path.startswith("/api2/json/nodes/restore01/tasks/UPID%3Arestore01%3A00001234")


# ── endpoints and mapping ──────────────────────────────────────────────────────


def test_nodes_cluster_network_storage(srv: Server) -> None:
    srv.route("GET", "/nodes", data([{"node": "restore01", "status": "online"}]))
    srv.route(
        "GET",
        "/cluster/status",
        data([{"type": "cluster", "name": "prod"}, {"type": "node", "name": "restore01"}]),
    )
    srv.route("GET", "/nodes/restore01/network", data([{"iface": "vmbr99", "type": "bridge"}]))
    srv.route("GET", "/nodes/restore01/storage", data([{"storage": "pbs", "type": "pbs", "active": 1}]))
    c = srv.client()
    assert c.node_names() == ["restore01"]
    assert c.cluster_name() == "prod"
    assert c.node_networks() == [{"iface": "vmbr99", "type": "bridge"}]
    assert c.storage_list()[0]["type"] == "pbs"
    srv.route("GET", "/cluster/status", data([{"type": "node", "name": "restore01"}]))
    assert c.cluster_name() is None


def test_list_backups_mapping_and_filter(srv: Server) -> None:
    items = [
        {
            "volid": "pbs:backup/vm/105/2026-10-01T02:00:00Z",
            "vmid": 105,
            "ctime": 1759284000,
            "size": 1234,
            "format": "pbs-vm",
            "content": "backup",
            "notes": "web01",
            "verification": {"state": "ok", "upid": "x"},
            "encrypted": "aa:bb",
        },
        {
            "volid": "pbs:backup/vm/106/2026-10-01T02:00:00Z",
            "vmid": "106",
            "ctime": "1759284001",
            "format": "pbs-vm",
            "content": "backup",
            "verification": {"state": "failed"},
        },
        {
            "volid": "local:backup/vzdump-qemu-107.vma.zst",
            "vmid": 107,
            "ctime": 5,
            "format": "vma.zst",
            "content": "backup",
        },
        {"volid": "pbs:backup/ct/200/2026", "vmid": 200, "ctime": 1, "format": "pbs-ct", "content": "backup"},
        {
            "volid": "local:backup/vzdump-lxc-201.tar.zst",
            "vmid": 201,
            "ctime": 1,
            "format": "tar.zst",
            "content": "backup",
        },
        {"volid": "local:iso/x.iso", "ctime": 1, "format": "iso", "content": "iso"},
    ]
    srv.route("GET", "/nodes/restore01/storage/pbs/content", data(items))
    refs = srv.client().list_backups("pbs")
    assert srv.requests[0].query == {"content": ["backup"]}
    assert [r.vmid for r in refs] == [105, 106, 107]
    a, b, c = refs
    assert (a.ctime, a.size, a.notes, a.verified, a.encrypted, a.format) == (
        1759284000,
        1234,
        "web01",
        True,
        True,
        "pbs-vm",
    )
    assert (b.ctime, b.size, b.verified, b.encrypted) == (1759284001, 0, False, None)
    assert (c.verified, c.encrypted, c.format) == (None, None, "vma.zst")


def test_list_vms_and_config(srv: Server) -> None:
    srv.route("GET", Q, data([{"vmid": "900105", "name": "web01", "status": "running"}, {"vmid": 100}]))
    srv.route("GET", f"{Q}/900105/config", data({"memory": 2048, "name": "web01", "onboot": 1}))
    c = srv.client()
    vms = c.list_vms()
    assert vms[0] == {"vmid": 900105, "name": "web01", "status": "running", "tags": ""}
    assert vms[1]["vmid"] == 100
    assert c.get_vm_config(900105) == {"memory": "2048", "name": "web01", "onboot": "1"}


def test_vm_exists(srv: Server) -> None:
    srv.route("GET", f"{Q}/900105/config", data({"name": "x"}))
    srv.route(
        "GET",
        f"{Q}/900106/config",
        Reply(500, {"data": None}, "Configuration file 'nodes/restore01/qemu-server/900106.conf' does not exist"),
    )
    srv.route("GET", f"{Q}/900107/config", Reply(403, {"data": None}, "Permission check failed"))
    c = srv.client()
    assert c.vm_exists(900105) is True
    assert c.vm_exists(900106) is False
    with pytest.raises(ApiError) as ei:
        c.vm_exists(900107)
    assert ei.value.status == 403


def test_update_config_uses_put_with_delete_list(srv: Server) -> None:
    srv.route("PUT", f"{Q}/900105/config", data(None))
    c = srv.client()
    c.update_vm_config(900105, {"onboot": "0", "tags": "pbv-temp"}, ["protection", "hostpci0"])
    c.update_vm_config(900105, {}, [])  # no-op: nothing sent
    (req,) = srv.requests
    assert req.method == "PUT"
    assert req.form == {"onboot": ["0"], "tags": ["pbv-temp"], "delete": ["protection,hostpci0"]}


def test_status_start_stop_destroy(srv: Server) -> None:
    srv.route("GET", f"{Q}/900105/status/current", data({"status": "running", "vmid": 900105}))
    srv.route("POST", f"{Q}/900105/status/(start|stop)", data(UPID))
    srv.route("DELETE", f"{Q}/900105", data(UPID))
    c = srv.client()
    assert c.vm_status(900105) == "running"
    assert c.start_vm(900105) == UPID
    assert c.stop_vm(900105) == UPID
    assert c.stop_vm(900105, skiplock=True) == UPID
    assert c.destroy_vm(900105) == UPID
    assert c.destroy_vm(900105, skiplock=True) == UPID
    _, start, stop1, stop2, d1, d2 = srv.requests
    assert start.form == {}
    assert stop1.form == {}
    assert stop2.form == {"skiplock": ["1"]}
    assert d1.query == {"purge": ["1"], "destroy-unreferenced-disks": ["1"]}
    assert d2.query == {"purge": ["1"], "destroy-unreferenced-disks": ["1"], "skiplock": ["1"]}
    assert d2.body == b""


def test_non_upid_response_is_error(srv: Server) -> None:
    srv.route("POST", f"{Q}/900105/status/start", data(None))
    with pytest.raises(ApiError) as ei:
        srv.client().start_vm(900105)
    assert ei.value.code == "API_BAD_RESPONSE"


def test_monitor(srv: Server) -> None:
    srv.route("POST", f"{Q}/900105/monitor", data("screendump done\n"))
    assert srv.client().monitor(900105, "screendump /x.png -f png") == "screendump done\n"
    assert srv.requests[0].form == {"command": ["screendump /x.png -f png"]}


# ── errors and retries ─────────────────────────────────────────────────────────


def test_error_parsing_message_and_errors(srv: Server) -> None:
    srv.route(
        "POST",
        Q,
        Reply(
            400,
            {"data": None, "errors": {"vmid": "invalid format", "storage": "missing"}},
            "Parameter verification failed.",
        ),
    )
    with pytest.raises(ApiError) as ei:
        srv.client().restore_vm(1, "x", "y")
    e = ei.value
    assert e.status == 400
    assert e.transient is False
    msg = str(e)
    assert "Parameter verification failed." in msg
    assert "storage: missing" in msg
    assert "vmid: invalid format" in msg
    assert "POST /nodes/restore01/qemu" in msg


def test_error_message_from_body_and_401_hint(srv: Server) -> None:
    srv.route("GET", "/version", Reply(401, {"data": None, "message": "authentication failure\n"}, "x"))
    with pytest.raises(ApiError) as ei:
        srv.client().version()
    assert "authentication failure" in str(ei.value)
    assert "check target.token_id" in str(ei.value)


def test_non_json_success_is_error(srv: Server) -> None:
    srv.route("GET", "/version", Reply(200, b"<html>"))
    with pytest.raises(ApiError) as ei:
        srv.client().version()
    assert ei.value.code == "API_BAD_RESPONSE"


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (503, "Service Unavailable"),
        (502, "Bad Gateway"),
        (504, "Gateway Timeout"),
        (500, "VM 1 qmp command failed - got timeout"),
    ],
)
def test_transient_get_is_retried_with_backoff(srv: Server, status: int, reason: str) -> None:
    calls = {"n": 0}

    def flaky(req: object) -> Reply | dict[str, object]:
        calls["n"] += 1
        return Reply(status, {"data": None}, reason) if calls["n"] < 3 else data({"version": "9"})

    srv.route("GET", "/version", flaky)
    sleeps: list[float] = []
    assert srv.client(sleep=sleeps.append).version() == {"version": "9"}
    assert len(srv.requests) == 3
    assert len(sleeps) == 2
    assert 0.5 <= sleeps[0] <= 1.0
    assert 1.0 <= sleeps[1] <= 2.0


def test_transient_get_gives_up_after_retries(srv: Server) -> None:
    srv.route("GET", "/version", Reply(503, {"data": None}, "busy"))
    sleeps: list[float] = []
    with pytest.raises(ApiError) as ei:
        srv.client(sleep=sleeps.append, retries=3, jitter=lambda: 1.0).version()
    assert ei.value.transient is True
    assert ei.value.status == 503
    assert len(srv.requests) == 4
    assert sleeps == [1.0, 2.0, 4.0]


def test_final_error_not_retried(srv: Server) -> None:
    srv.route("GET", "/version", Reply(500, {"data": None}, "something broke"))
    sleeps: list[float] = []
    with pytest.raises(ApiError) as ei:
        srv.client(sleep=sleeps.append).version()
    assert ei.value.transient is False
    assert len(srv.requests) == 1
    assert sleeps == []


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_mutating_request_not_retried_after_http_5xx(srv: Server, method: str) -> None:
    srv.route(method, f"{Q}.*", Reply(503, {"data": None}, "busy"))
    c = srv.client()
    call = {
        "POST": lambda: c.start_vm(900105),
        "PUT": lambda: c.update_vm_config(900105, {"a": "1"}),
        "DELETE": lambda: c.destroy_vm(900105),
    }[method]
    with pytest.raises(ApiError) as ei:
        call()
    assert ei.value.transient is True
    assert len(srv.requests) == 1


def test_post_not_retried_after_connection_drop(srv: Server) -> None:
    srv.route("POST", Q, lambda req: DROP)
    sleeps: list[float] = []
    with pytest.raises(ApiError) as ei:
        srv.client(sleep=sleeps.append).restore_vm(900105, "pbs:backup/vm/105/x", "local-lvm")
    assert ei.value.status is None
    assert ei.value.transient is True
    assert "after sending request" in str(ei.value)
    assert len(srv.reqs("POST")) == 1
    assert sleeps == []


def test_get_retried_after_connection_drop(srv: Server) -> None:
    calls = {"n": 0}

    def drop_once(req: object) -> object:
        calls["n"] += 1
        return DROP if calls["n"] == 1 else data({"version": "9"})

    srv.route("GET", "/version", drop_once)
    assert srv.client().version() == {"version": "9"}
    assert len(srv.requests) == 2


def test_get_read_timeout_is_transient_and_retried(srv: Server) -> None:
    srv.route("GET", "/version", Reply(200, {"data": {}}, delay_s=0.6))
    sleeps: list[float] = []
    with pytest.raises(ApiError) as ei:
        srv.client(timeout_s=0.2, retries=1, sleep=sleeps.append).version()
    assert ei.value.transient is True
    assert ei.value.status is None
    assert len(sleeps) == 1


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_connection_refused_retried_for_any_method(srv: Server, closed_port: int, method: str) -> None:
    sleeps: list[float] = []
    c = srv.client(port=closed_port, sleep=sleeps.append, retries=2)
    with pytest.raises(ApiError) as ei:
        c.version() if method == "GET" else c.start_vm(900105)
    e = ei.value
    assert e.status is None
    assert e.transient is True
    assert e.code == "API_UNREACHABLE"
    assert len(sleeps) == 2
    assert SECRET not in str(e)


# ── wait_task ──────────────────────────────────────────────────────────────────

TASK = "/nodes/restore01/tasks/[^/]+"


def _task_log_route(srv: Server, n_lines: int) -> None:
    lines = [{"n": i + 1, "t": f"line {i + 1}"} for i in range(n_lines)]

    def handler(req: object) -> dict[str, object]:
        q = req.query  # type: ignore[attr-defined]
        start, limit = int(q["start"][0]), int(q["limit"][0])
        return {"data": lines[start : start + limit], "total": n_lines}

    srv.route("GET", f"{TASK}/log", handler)


def test_wait_task_success_polls(srv: Server, clock: FakeClock) -> None:
    states = iter([{"status": "running"}, {"status": "running"}, {"status": "stopped", "exitstatus": "OK"}])
    srv.route("GET", f"{TASK}/status", lambda req: data(next(states)))
    c = srv.client(sleep=clock.sleep, clock=clock, task_poll_s=2.0)
    res = c.wait_task(UPID, 60)
    assert res.ok is True
    assert res.exitstatus == "OK"
    assert res.upid == UPID
    assert res.log_tail == ()
    assert clock.sleeps == [2.0, 2.0]
    assert not srv.reqs(path_contains="/log")


def test_wait_task_failure_has_log_tail(srv: Server, clock: FakeClock) -> None:
    srv.route("GET", f"{TASK}/status", data({"status": "stopped", "exitstatus": "unable to restore: no space"}))
    _task_log_route(srv, 57)
    res = srv.client(sleep=clock.sleep, clock=clock).wait_task(UPID, 60)
    assert res.ok is False
    assert res.exitstatus == "unable to restore: no space"
    assert res.log_tail == tuple(f"line {i}" for i in range(38, 58))
    tail_req = srv.reqs(path_contains="/log")[-1]
    assert tail_req.query == {"start": ["37"], "limit": ["20"]}


def test_wait_task_warnings_is_ok_with_tail(srv: Server, clock: FakeClock) -> None:
    srv.route("GET", f"{TASK}/status", data({"status": "stopped", "exitstatus": "WARNINGS: 1"}))
    _task_log_route(srv, 3)
    res = srv.client(sleep=clock.sleep, clock=clock).wait_task(UPID, 60)
    assert res.ok is True
    assert res.log_tail == ("line 1", "line 2", "line 3")


def test_wait_task_log_failure_does_not_mask_result(srv: Server, clock: FakeClock) -> None:
    srv.route("GET", f"{TASK}/status", data({"status": "stopped", "exitstatus": "failed"}))
    srv.route("GET", f"{TASK}/log", Reply(403, {"data": None}, "no"))
    res = srv.client(sleep=clock.sleep, clock=clock).wait_task(UPID, 60)
    assert res.ok is False
    assert res.log_tail[0].startswith("(task log unavailable")


def test_wait_task_timeout(srv: Server, clock: FakeClock) -> None:
    srv.route("GET", f"{TASK}/status", data({"status": "running"}))
    with pytest.raises(PbvTimeoutError) as ei:
        srv.client(sleep=clock.sleep, clock=clock, task_poll_s=2.0).wait_task(UPID, 5)
    assert ei.value.code == "TASK_TIMEOUT"
    assert UPID in str(ei.value)
    assert clock.sleeps == [2.0, 2.0, 1.0]


def test_task_log_limit(srv: Server) -> None:
    _task_log_route(srv, 5)
    assert srv.client().task_log(UPID, limit=2) == ["line 4", "line 5"]


# ── guest agent endpoints ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason",
    [
        "QEMU guest agent is not running",
        "VM 900105 is not running",
        "No QEMU guest agent configured",
        "VM 900105 qmp command 'guest-ping' failed - got timeout",
    ],
)
def test_agent_ping_false_when_agent_down(srv: Server, reason: str) -> None:
    srv.route("POST", f"{Q}/900105/agent/ping", Reply(500, {"data": None}, reason))
    assert srv.client().agent_ping(900105) is False
    assert len(srv.requests) == 1


def test_agent_ping_true_and_other_errors_raise(srv: Server) -> None:
    srv.route("POST", f"{Q}/900105/agent/ping", data({"result": {}}))
    srv.route("POST", f"{Q}/900106/agent/ping", Reply(500, {"data": None}, "storage exploded"))
    srv.route("POST", f"{Q}/900107/agent/ping", Reply(403, {"data": None}, "VM.Monitor missing"))
    c = srv.client()
    assert c.agent_ping(900105) is True
    with pytest.raises(ApiError):
        c.agent_ping(900106)
    with pytest.raises(ApiError):
        c.agent_ping(900107)


def test_agent_exec_status_decoded_fields(srv: Server) -> None:
    srv.route(
        "GET",
        f"{Q}/900105/agent/exec-status",
        data(
            {
                "exited": 1,
                "exitcode": 3,
                "out-data": "active\n",
                "err-data": base64.b64encode(b"boom").decode(),
                "out-truncated": 1,
            }
        ),
    )
    st = srv.client().agent_exec_status(900105, 77)
    assert srv.requests[0].query == {"pid": ["77"]}
    assert st.exited is True
    assert st.exitcode == 3
    assert st.stdout == "active\n"
    assert st.stderr == "boom"
    assert st.out_truncated is True
    assert st.err_truncated is False
    assert st.signal is None


def test_agent_exec_status_running(srv: Server) -> None:
    srv.route("GET", f"{Q}/900105/agent/exec-status", data({"exited": 0}))
    st = srv.client().agent_exec_status(900105, 1)
    assert st.exited is False
    assert st.exitcode is None


def test_b64_heuristic() -> None:
    enc = base64.b64encode("héllo wörld".encode()).decode()
    assert _maybe_b64(enc, None) == "héllo wörld"
    assert _maybe_b64("active\n", None) == "active\n"  # whitespace → raw
    assert _maybe_b64("true", None) == "true"  # valid b64 but not UTF-8 → raw
    assert _maybe_b64("abc", None) == "abc"  # bad length
    assert _maybe_b64(enc, False) == enc  # flag off
    assert _maybe_b64("not base64!", True) == "not base64!"  # invalid → raw
    assert _maybe_b64("", None) == ""


def test_agent_exec_rejects_non_utf8_input(srv: Server) -> None:
    with pytest.raises(GuestAgentError):
        srv.client().agent_exec(900105, ["cat"], input_data=b"\xff\xfe")
    with pytest.raises(GuestAgentError):
        srv.client().agent_exec(900105, [])
    assert srv.requests == []


def test_agent_file_write_encodes_base64(srv: Server) -> None:
    srv.route("POST", f"{Q}/900105/agent/file-write", data(None))
    content = b"#!/bin/sh\n\xff\x00binary\n"
    srv.client().agent_file_write(900105, "/tmp/pbv-x.sh", content)
    (req,) = srv.requests
    assert req.form["file"] == ["/tmp/pbv-x.sh"]
    assert req.form["encode"] == ["0"]
    assert base64.b64decode(req.form["content"][0]) == content


def test_agent_file_write_too_large(srv: Server) -> None:
    srv.route("POST", f"{Q}/900105/agent/file-write", data(None))
    c = srv.client()
    c.agent_file_write(900105, "/tmp/ok", b"x" * FILE_WRITE_MAX_BYTES)
    with pytest.raises(GuestAgentError):
        c.agent_file_write(900105, "/tmp/big", b"x" * (FILE_WRITE_MAX_BYTES + 1))
    assert len(srv.requests) == 1


def test_agent_osinfo_and_interfaces_unwrap_result(srv: Server) -> None:
    srv.route("GET", f"{Q}/900105/agent/get-osinfo", data({"result": {"id": "debian"}}))
    srv.route(
        "GET",
        f"{Q}/900105/agent/network-get-interfaces",
        data({"result": [{"name": "eth0", "ip-addresses": []}]}),
    )
    c = srv.client()
    assert c.agent_osinfo(900105) == {"id": "debian"}
    assert c.agent_network_interfaces(900105) == [{"name": "eth0", "ip-addresses": []}]


# ── TLS ────────────────────────────────────────────────────────────────────────


def test_fingerprint_pin_match_accepts_colon_format(srv: Server) -> None:
    srv.route("GET", "/version", data({"version": "9"}))
    pin = ":".join(srv.fingerprint[i : i + 2] for i in range(0, 64, 2)).upper()
    assert normalize_fingerprint(pin) == srv.fingerprint
    assert srv.client(fingerprint=pin).version() == {"version": "9"}


def test_fingerprint_pin_mismatch_sends_nothing(srv: Server) -> None:
    srv.route("GET", "/version", data({"version": "9"}))
    sleeps: list[float] = []
    with pytest.raises(ApiError) as ei:
        srv.client(fingerprint="00" * 32, sleep=sleeps.append).version()
    e = ei.value
    assert e.code == "TLS_PIN_MISMATCH"
    assert e.transient is False
    assert e.status is None
    assert srv.fingerprint[:2].upper() in str(e)
    assert srv.requests == []
    assert sleeps == []


def test_verify_with_ca_file(srv: Server) -> None:
    srv.route("GET", "/version", data({"version": "9"}))
    assert srv.client(fingerprint="", ca_file=str(srv.cert_file)).version() == {"version": "9"}


def test_verify_fails_without_ca_file(srv: Server) -> None:
    sleeps: list[float] = []
    with pytest.raises(ApiError) as ei:
        srv.client(fingerprint="", sleep=sleeps.append).version()
    assert ei.value.code == "TLS_VERIFY_FAIL"
    assert ei.value.transient is False
    assert srv.requests == []
    assert sleeps == []


def test_verify_disabled_warns(srv: Server, caplog: pytest.LogCaptureFixture) -> None:
    srv.route("GET", "/version", data({"version": "9"}))
    with caplog.at_level(logging.WARNING, logger="pbv.pve"):
        c = srv.client(fingerprint="", verify_tls=False)
    assert "TLS_VERIFY_DISABLED" in caplog.text
    assert c.version() == {"version": "9"}


# ── secrets ────────────────────────────────────────────────────────────────────


def test_secret_absent_from_repr_errors_and_logs(
    srv: Server, closed_port: int, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    c = srv.client()
    assert SECRET not in repr(c)
    assert SECRET not in str(vars(c))
    srv.route("GET", "/version", Reply(401, {"data": None, "message": f"bad token {SECRET}"}, "auth"))
    srv.route("POST", Q, lambda req: DROP)
    failures = [
        c.version,
        lambda: c.restore_vm(1, "a", "b"),
        srv.client(port=closed_port).version,
        srv.client(fingerprint="11" * 32).version,
        srv.client(fingerprint="").version,
    ]
    for fail in failures:
        with pytest.raises(ApiError) as ei:
            fail()
        assert SECRET not in str(ei.value)
        assert SECRET not in repr(ei.value)
    assert SECRET not in caplog.text


def test_from_config(srv: Server) -> None:
    target = TargetConfig(
        host="127.0.0.1",
        node="restore01",
        token_id=TOKEN_ID,
        token_secret=SECRET,
        port=srv.port,
        fingerprint=srv.fingerprint,
        api_timeout_s=5,
        api_retries=1,
    )
    srv.route("GET", "/version", data({"version": "9"}))
    c = PveClient.from_config(target, sleep=lambda s: None)
    assert c.node == "restore01"
    assert c.version() == {"version": "9"}
    assert SECRET not in repr(c)
