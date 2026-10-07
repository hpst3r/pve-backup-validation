"""A8: every sanitize rule of SPEC §3."""

from __future__ import annotations

import pytest

from pbv.config import SanitizeConfig
from pbv.orchestrator import SanitizePlan, sanitize_config

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
