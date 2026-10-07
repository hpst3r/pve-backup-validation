"""A8: every sanitize rule of SPEC §3."""

from __future__ import annotations

import pytest

from pbv.config import SanitizeConfig
from pbv.orchestrator import PRIVILEGED_KEY, PrivilegedSplit, SanitizePlan, sanitize_config, split_privileged
from pbv.testing import fakes

STORAGES = {"local-lvm", "pbs", "local"}


def plan(cfg: dict[str, str], **opts: object) -> SanitizePlan:
    p = sanitize_config(
        {"agent": "1", **cfg}, bridge="vmbr99", storages=STORAGES, opts=SanitizeConfig(**opts), vmid=900105
    )
    assert not set(p.set) & set(p.delete), "set and delete must be disjoint"
    return p


def test_already_clean_config_is_a_noop():
    p = plan({"name": "x", "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr99,firewall=0", "onboot": "0"})
    assert p == SanitizePlan()


def test_net_moved_to_isolated_bridge_keeping_model_mac_and_other_options():
    p = plan({"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1,tag=10,trunks=1;2,rate=5,link_down=1,mtu=1400"})
    assert p.set["net0"] == "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr99,firewall=0,mtu=1400"
    assert p.notes == [
        "net0: bridge vmbr0 → vmbr99, firewall off, removed tag=10, removed trunks=1;2, removed rate=5, removed link_down=1"
    ]


def test_net_without_bridge_or_firewall_gets_both():
    p = plan({"net1": "e1000=AA:BB:CC:DD:EE:01"})
    assert p.set["net1"] == "e1000=AA:BB:CC:DD:EE:01,bridge=vmbr99,firewall=0"


@pytest.mark.parametrize("key", ["hostpci0", "usb1", "parallel0", "virtiofs0"])
def test_passthrough_removed(key):
    p = plan({key: "0000:01:00.0,pcie=1"})
    assert p.delete == [key]
    assert p.notes == [f"{key}: removed passthrough (0000:01:00.0,pcie=1)"]


def test_serial_socket_kept_device_removed():
    p = plan({"serial0": "socket", "serial1": "/dev/ttyS1"})
    assert p.delete == ["serial1"]
    assert p.notes == ["serial1: removed host serial device /dev/ttyS1"]


def test_serial_socket_removed_when_keep_serial_false():
    p = plan({"serial0": "socket"}, keep_serial=False)
    assert p.delete == ["serial0"]


@pytest.mark.parametrize("key", ["ide2", "sata1", "scsi3"])
def test_iso_ejected(key):
    p = plan({key: "local:iso/debian-12.iso,media=cdrom,size=600M"})
    assert p.set == {key: "none,media=cdrom"}
    assert p.notes == [f"{key}: ejected ISO local:iso/debian-12.iso"]


def test_iso_on_missing_storage_is_ejected_not_deleted():
    p = plan({"ide2": "nas-iso:iso/x.iso,media=cdrom"})
    assert p.set == {"ide2": "none,media=cdrom"} and p.delete == [] and p.warnings == []


@pytest.mark.parametrize("value", ["none,media=cdrom", "cdrom,media=cdrom"])
def test_empty_cdrom_untouched(value):
    assert plan({"ide2": value}) == SanitizePlan()


def test_cloud_init_drive_preserved():
    p = plan({"ide2": "local-lvm:vm-900105-cloudinit,media=cdrom", "scsi1": "local-lvm:vm-105-cloudinit,media=cdrom"})
    assert p == SanitizePlan()


@pytest.mark.parametrize("key", ["scsi0", "virtio1", "sata0", "ide0", "efidisk0", "tpmstate0", "unused3"])
def test_disk_on_missing_storage_removed_with_warning(key):
    p = plan({key: "ceph-pool:vm-900105-disk-1,size=32G"})
    assert p.delete == [key]
    assert p.warnings == [f"{key}: disk on missing storage ceph-pool removed"]
    assert p.notes == []


def test_disk_on_present_storage_kept():
    assert (
        plan({"scsi0": "local-lvm:vm-900105-disk-0,size=32G", "efidisk0": "local-lvm:vm-900105-disk-1"})
        == SanitizePlan()
    )


def test_raw_device_removed_with_warning():
    p = plan({"virtio1": "/dev/disk/by-id/ata-XYZ,backup=0"})
    assert p.delete == ["virtio1"]
    assert p.warnings == ["virtio1: raw device /dev/disk/by-id/ata-XYZ removed"]


def test_file_option_volume_is_parsed():
    p = plan({"scsi2": "file=gone:vm-1-disk-0,size=1G"})
    assert p.delete == ["scsi2"]


def test_scsihw_is_not_a_disk():
    assert plan({"scsihw": "virtio-scsi-single"}) == SanitizePlan()


@pytest.mark.parametrize("key", ["hookscript", "args", "startup", "affinity", "hugepages"])
def test_host_specific_options_removed(key):
    p = plan({key: "something"})
    assert p.delete == [key]
    assert p.notes == [f"{key}: removed host-specific option (something)"]


def test_onboot_forced_off_and_idempotent():
    assert plan({"onboot": "1"}).set == {"onboot": "0"}
    assert plan({"onboot": "0"}).set == {}
    assert plan({}).set == {}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "1"),
        ("0", "1"),
        ("0,fstrim_cloned_disks=1", "1,fstrim_cloned_disks=1"),
        ("enabled=0,type=virtio", "enabled=1,type=virtio"),
        ("type=isa", "enabled=1,type=isa"),
    ],
)
def test_agent_enabled_preserving_options(value, expected):
    cfg = {} if value is None else {"agent": value}
    p = sanitize_config(cfg, bridge="vmbr99", storages=STORAGES, opts=SanitizeConfig(), vmid=1)
    assert p.set == {"agent": expected}
    assert p.notes == ["agent: enabled guest agent"]


@pytest.mark.parametrize("value", ["1", "1,fstrim_cloned_disks=1", "enabled=1,type=virtio"])
def test_agent_already_enabled_untouched(value):
    assert plan({"agent": value}) == SanitizePlan()


def test_cpu_override_records_old_value():
    p = plan({"cpu": "host"}, cpu_override="x86-64-v2-AES")
    assert p.set == {"cpu": "x86-64-v2-AES"}
    assert p.notes == ["cpu: host → x86-64-v2-AES"]
    assert plan({"cpu": "x86-64-v2-AES"}, cpu_override="x86-64-v2-AES").set == {}
    assert plan({}, cpu_override="kvm64").notes == ["cpu: (default) → kvm64"]
    assert plan({"cpu": "host"}).set == {}


def test_memory_capped_and_balloon_follows():
    p = plan({"memory": "65536", "balloon": "32768"}, memory_max_mib=8192)
    assert p.set == {"memory": "8192", "balloon": "8192"}
    assert p.notes == ["balloon: 32768 → 8192 MiB", "memory: 65536 → 8192 MiB"]


def test_memory_property_string_and_small_values():
    assert plan({"memory": "current=16384"}, memory_max_mib=4096).set == {"memory": "4096"}
    assert plan({"memory": "2048", "balloon": "1024"}, memory_max_mib=4096).set == {}
    assert plan({"memory": "65536"}).set == {}  # 0 = no cap


def test_vga_set_when_configured():
    assert plan({"vga": "qxl"}, vga="std").set == {"vga": "std"}
    assert plan({"vga": "std"}, vga="std").set == {}
    assert plan({"vga": "qxl"}).set == {}


def test_notes_sorted_by_key_and_set_delete_disjoint():
    cfg = {
        "usb0": "host=1-2",
        "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
        "args": "-foo",
        "ide2": "local:iso/a.iso,media=cdrom",
        "onboot": "1",
        "agent": "0",
        "scsi1": "gone:vm-1-disk-0",
    }
    p = sanitize_config(cfg, bridge="vmbr99", storages=STORAGES, opts=SanitizeConfig(vga="std"), vmid=1)
    keys = [n.split(":", 1)[0] for n in p.notes]
    assert keys == sorted(keys)
    assert p.delete == sorted(p.delete) == ["args", "scsi1", "usb0"]
    assert not set(p.set) & set(p.delete)
    assert set(p.set) == {"net0", "ide2", "onboot", "agent", "vga"}


# ── SPEC §1a: split into API and root-only parts ───────────────────────────────
def split(cfg: dict[str, str], *, have_root: bool, **opts: object) -> PrivilegedSplit:
    return split_privileged(plan(cfg, **opts), {"agent": "1", **cfg}, have_root=have_root)


def test_privileged_regex_mirrors_fakes():
    assert PRIVILEGED_KEY.pattern == fakes.PRIVILEGED_KEY.pattern


def test_split_returns_four_parts_and_sorted_root_keys():
    s = split(
        {"usb1": "host=1234:5678", "hostpci0": "host=0000:01:00.0", "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"},
        have_root=True,
    )
    api_set, api_delete, root_set, root_delete = s
    assert list(api_set) == ["net0"] and api_delete == []
    assert root_set == {} and root_delete == ["hostpci0", "usb1"]
    assert s.root_keys == ["hostpci0", "usb1"]


@pytest.mark.parametrize(
    "cfg",
    [
        {"hostpci0": "mapping=gpu"},
        {"hostpci0": "host=0000:01:00.0,pcie=1"},
        {"usb0": "spice"},
        {"usb0": "mapping=stick"},
        {"parallel0": "/dev/parport0"},
        {"virtiofs0": "share1"},
        {"args": "-cpu host"},
        {"hookscript": "local:snippets/h.pl"},
        {"serial0": "/dev/ttyS0"},
    ],
)
def test_with_node_shell_every_privileged_key_goes_to_root(cfg):
    _, api_delete, root_set, root_delete = split(cfg, have_root=True)
    assert root_delete == list(cfg) and not api_delete and not root_set


@pytest.mark.parametrize(
    ("cfg", "root"),
    [
        ({"hostpci0": "host=0000:01:00.0,pcie=1"}, True),
        ({"hostpci1": "0000:02:00.0"}, True),  # legacy positional host
        ({"hostpci0": "mapping=gpu,pcie=1"}, False),  # mapped: Mapping.Use suffices, try the API
        ({"usb0": "host=1234:5678"}, True),
        ({"usb1": "1-1.2"}, True),
        ({"usb0": "mapping=stick"}, False),
        ({"usb0": "spice"}, False),
        ({"usb0": "host=spice,usb3=1"}, False),
        ({"parallel0": "/dev/parport0"}, True),
        ({"virtiofs0": "share1"}, True),
        ({"args": "-cpu host"}, True),
        ({"hookscript": "local:snippets/h.pl"}, True),
        ({"serial0": "/dev/ttyS0"}, True),
    ],
)
def test_without_node_shell_only_known_root_changes_go_to_root(cfg, root):
    _, api_delete, root_set, root_delete = split(cfg, have_root=False)
    assert not root_set
    assert (root_delete, api_delete) == ((list(cfg), []) if root else ([], list(cfg)))


@pytest.mark.parametrize("have_root", [True, False])
def test_socket_serial_stays_on_api_side(have_root):
    s = split({"serial0": "socket"}, have_root=have_root, keep_serial=False)
    assert s.api_delete == ["serial0"] and s.root_keys == []
    assert split({"serial0": "socket"}, have_root=have_root) == ({}, [], {}, [])  # kept: nothing to do


def test_split_set_values_and_serial_device_changes():
    p = SanitizePlan(set={"serial0": "socket", "args": "-x", "vga": "std"}, delete=["serial1"])
    s = split_privileged(p, {"serial0": "/dev/ttyS0", "serial1": "socket"}, have_root=True)
    assert s.api_set == {"vga": "std"} and s.api_delete == ["serial1"]
    assert s.root_set == {"serial0": "socket", "args": "-x"} and s.root_delete == []
    s = split_privileged(p, {"serial0": "/dev/ttyS0", "serial1": "socket"}, have_root=False)
    assert s.root_set == {"serial0": "socket", "args": "-x"}  # device → socket is still root-only
