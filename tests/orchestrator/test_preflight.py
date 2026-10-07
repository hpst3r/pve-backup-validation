"""A1: preflight guards (SPEC §1)."""

from __future__ import annotations

import pytest

from pbv.core import ApiError, PreflightError, Status
from pbv.orchestrator import PreflightFailure, preflight
from pbv.testing.fakes import FakeNodeShell, FakePve, FakeStorage

from .conftest import make_cfg

STEP_NAMES = ["version", "node", "standalone", "bridge", "backup_storage", "target_storage", "temp_range"]


def fails_at(pve: FakePve, cfg, step: str, needle: str = "", **kw) -> PreflightError:
    with pytest.raises(PreflightError) as ei:
        preflight(pve, cfg, **kw)
    exc = ei.value
    assert exc.code == "PREFLIGHT_FAIL"
    names = STEP_NAMES if cfg.node_shell.mode == "off" else [*STEP_NAMES[:1], "node_shell", *STEP_NAMES[1:]]
    assert [s.name for s in exc.steps] == names[: names.index(step) + 1]
    last = exc.steps[-1]
    assert last.status in (Status.FAIL, Status.ERROR) and last.error_code == "PREFLIGHT_FAIL"
    assert all(s.status is Status.PASS for s in exc.steps[:-1])
    assert needle in last.message
    return exc


def test_all_guards_pass(tmp_path):
    pve = FakePve()
    pve.add_vm(900200, {"name": "left", "tags": "pbv-temp"})
    pve.add_vm(105, {"name": "prod"})  # outside the temp range: ignored
    steps = preflight(pve, make_cfg(tmp_path))
    assert [s.name for s in steps] == STEP_NAMES
    assert all(s.status is Status.PASS and not s.error_code for s in steps)
    assert "9.0.10" in steps[0].message
    assert not [
        c for c in pve.calls if c[0] not in {"version", "cluster_status", "node_networks", "storage_list", "list_vms"}
    ]


def test_refuses_clustered_node(tmp_path):
    pve = FakePve(cluster=[{"type": "cluster", "name": "prod"}, {"type": "node", "name": "restore01", "local": 1}])
    fails_at(pve, make_cfg(tmp_path), "standalone", "cluster 'prod'")


def test_refuses_forbidden_cluster_name_when_clustering_allowed(tmp_path):
    pve = FakePve(cluster=[{"type": "cluster", "name": "prod"}, {"type": "node", "name": "restore01", "local": 1}])
    cfg = make_cfg(tmp_path, target={"require_standalone": False, "forbid_cluster_names": ["prod"]})
    fails_at(pve, cfg, "standalone", "forbid_cluster_names")


def test_allows_other_cluster_when_not_required_standalone(tmp_path):
    pve = FakePve(cluster=[{"type": "cluster", "name": "lab"}, {"type": "node", "name": "restore01", "local": 1}])
    cfg = make_cfg(tmp_path, target={"require_standalone": False, "forbid_cluster_names": ["prod"]})
    steps = preflight(pve, cfg)
    assert "lab" in steps[2].message


def test_refuses_unknown_node(tmp_path):
    pve = FakePve(cluster=[{"type": "node", "name": "other", "local": 1}])
    pve.node = "restore01"
    fails_at(pve, make_cfg(tmp_path), "node", "not found")


def test_refuses_node_not_served_by_api(tmp_path):
    pve = FakePve(
        cluster=[{"type": "node", "name": "restore01", "local": 0}, {"type": "node", "name": "x", "local": 1}]
    )
    fails_at(pve, make_cfg(tmp_path), "node", "served by node x")


def test_refuses_client_bound_to_other_node(tmp_path):
    pve = FakePve(node="elsewhere", cluster=[{"type": "node", "name": "restore01", "local": 1}])
    fails_at(pve, make_cfg(tmp_path), "node", "bound to node")


def test_refuses_bridge_with_ports(tmp_path):
    pve = FakePve()
    pve.networks[1]["bridge_ports"] = "eno2"
    fails_at(pve, make_cfg(tmp_path), "bridge", "has ports (eno2)")


@pytest.mark.parametrize("ports", [None, "", "none", "NONE"])
def test_bridge_without_ports_ok(tmp_path, ports):
    pve = FakePve()
    if ports is None:
        del pve.networks[1]["bridge_ports"]
    else:
        pve.networks[1]["bridge_ports"] = ports
    preflight(pve, make_cfg(tmp_path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cidr", "10.0.0.1/24"),
        ("address", "10.0.0.1"),
        ("cidr6", "fd00::1/64"),
        ("address6", "fd00::1"),
        ("gateway", "10.0.0.254"),
        ("gateway6", "fd00::fe"),
    ],
)
def test_refuses_bridge_with_ip(tmp_path, field, value):
    pve = FakePve()
    pve.networks[1][field] = value
    fails_at(pve, make_cfg(tmp_path), "bridge", f"{field}={value}")


def test_bridge_isolation_not_enforced_when_disabled(tmp_path):
    cfg = make_cfg(tmp_path, restore={"isolated_bridge": "vmbr0", "require_isolated_bridge": False})
    preflight(FakePve(), cfg)


def test_refuses_missing_bridge_and_non_bridge(tmp_path):
    fails_at(FakePve(), make_cfg(tmp_path, restore={"isolated_bridge": "vmbr7"}), "bridge", "does not exist")
    pve = FakePve()
    pve.networks.append({"iface": "bond0", "type": "bond"})
    fails_at(pve, make_cfg(tmp_path, restore={"isolated_bridge": "bond0"}), "bridge", "expected 'bridge'")


def test_refuses_non_pbs_backup_storage(tmp_path):
    pve = FakePve()
    pve.storages["pbs"] = FakeStorage("pbs", "dir", "backup")
    fails_at(pve, make_cfg(tmp_path), "backup_storage", "expected 'pbs'")


@pytest.mark.parametrize("field", ["active", "enabled"])
def test_refuses_inactive_backup_storage(tmp_path, field):
    pve = FakePve()
    setattr(pve.storages["pbs"], field, 0)
    fails_at(pve, make_cfg(tmp_path), "backup_storage", "not active and enabled")


def test_refuses_missing_backup_storage(tmp_path):
    fails_at(FakePve(), make_cfg(tmp_path, restore={"backup_storage": "nope"}), "backup_storage", "does not exist")


def test_refuses_target_storage_without_images(tmp_path):
    pve = FakePve()
    pve.storages["local-lvm"].content = "rootdir,iso"
    fails_at(pve, make_cfg(tmp_path), "target_storage", "images")


def test_refuses_inactive_target_storage(tmp_path):
    pve = FakePve()
    pve.storages["local-lvm"].active = 0
    fails_at(pve, make_cfg(tmp_path), "target_storage", "not active")


def test_refuses_untagged_vm_in_temp_range(tmp_path):
    pve = FakePve()
    pve.add_vm(900200, {"name": "foreign", "tags": "other"})
    pve.add_vm(900300, {"name": "ok", "tags": "x;pbv-temp"})
    exc = fails_at(pve, make_cfg(tmp_path), "temp_range", "900200")
    assert "900300" not in exc.steps[-1].message


def test_api_error_is_preflight_error(tmp_path):
    pve = FakePve()
    pve.fail_next["version"] = ApiError("connection refused", status=None)
    exc = fails_at(pve, make_cfg(tmp_path), "version", "connection refused")
    assert exc.steps[-1].status is Status.ERROR


# ── SPEC §1a: node_shell step ───────────────────────────────────────────────────
def test_node_shell_step_after_version_when_enabled(tmp_path):
    shell = FakeNodeShell()
    steps = preflight(FakePve(), make_cfg(tmp_path, node_shell={"mode": "local"}), shell)
    assert [s.name for s in steps] == ["version", "node_shell", *STEP_NAMES[1:]]
    assert steps[1].status is Status.PASS and steps[1].message == "fake node shell ok"


def test_node_shell_not_probed_when_off(tmp_path):
    class Exploding(FakeNodeShell):
        def probe(self) -> str:
            raise AssertionError("must not be probed")

    steps = preflight(FakePve(), make_cfg(tmp_path), node_shell=Exploding())
    assert "node_shell" not in [s.name for s in steps]


def test_node_shell_probe_failure_is_fatal(tmp_path):
    pve = FakePve()
    cfg = make_cfg(tmp_path, node_shell={"mode": "ssh", "ssh_host": "restore01"})
    exc = fails_at(pve, cfg, "node_shell", "ssh exited 255", node_shell=FakeNodeShell(fail=True))
    assert exc.steps[-1].status is Status.FAIL
    assert [c[0] for c in pve.calls] == ["version"]  # nothing after the failed step


def test_node_shell_configured_but_not_provided(tmp_path):
    fails_at(FakePve(), make_cfg(tmp_path, node_shell={"mode": "local"}), "node_shell", "configured but not provided")


def test_node_shell_without_probe_is_refused(tmp_path):
    class NoProbe:
        def qm_set(self, vmid, set_, delete): ...
        def screendump(self, vmid, dest): ...

    cfg = make_cfg(tmp_path, node_shell={"mode": "local"})
    fails_at(FakePve(), cfg, "node_shell", "cannot be probed", node_shell=NoProbe())


def test_preflight_failure_alias_is_core_error():
    assert PreflightFailure is PreflightError
