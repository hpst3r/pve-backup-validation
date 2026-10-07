"""Acceptance A16: config loader."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pbv.config import load_config, parse_config
from pbv.core import ConfigError, NotifyWhen, OsFamily

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "config.toml"


def base(tmp_path: Path, **over) -> dict:
    sec = tmp_path / "tok"
    sec.write_text("00000000-1111-2222-3333-444444444444\n")
    sec.chmod(0o600)
    raw = {
        "target": {"host": "h", "node": "n", "token_id": "pbv@pve!t", "token_secret_file": str(sec)},
        "restore": {"backup_storage": "pbs", "target_storage": "local-lvm", "isolated_bridge": "vmbr99"},
        "vm": [{"vmid": 105}],
    }
    for k, v in over.items():
        raw[k] = v
    return raw


def test_example_config_loads(tmp_path, monkeypatch):
    # The example references secrets/pve-token relative to examples/; provide via a copy.
    d = tmp_path / "ex"
    d.mkdir()
    (d / "config.toml").write_text(EXAMPLE.read_text())
    (d / "secrets").mkdir()
    (d / "known_hosts").write_text("")
    for n in ("pve-token", "smtp-password", "id_ed25519"):
        (d / "secrets" / n).write_text("x")
        (d / "secrets" / n).chmod(0o600)
    (d / "scripts").mkdir()
    for s in (EXAMPLE.parent / "scripts").iterdir():
        (d / "scripts" / s.name).write_bytes(s.read_bytes())
        (d / "scripts" / s.name).chmod(s.stat().st_mode)
    cfg = load_config(d / "config.toml")
    assert cfg.target.node == "pbv-restore01"
    assert [v.vmid for v in cfg.vms] == [105, 110]
    vm105 = cfg.vms[0]
    assert [c.type for c in vm105.checks] == ["http", "script", "systemd"]
    assert vm105.checks[1].params["path"] == str((d / "scripts" / "check-app-db.sh").resolve())
    assert vm105.checks[1].params["env"] == {"APP_ENV": "restore-test"}
    assert cfg.vms[1].os is OsFamily.WINDOWS
    assert cfg.vms[1].checks[0].only_os is OsFamily.WINDOWS
    assert cfg.global_checks[0].only_os is OsFamily.LINUX
    assert cfg.temp_vmid(105) == 900105 and vm105.temp_vmid == 900105
    assert cfg.notify.json.when is NotifyWhen.ALWAYS
    assert cfg.node_shell.mode == "ssh" and cfg.node_shell.ssh_key_file == str(d / "secrets" / "id_ed25519")
    assert cfg.screenshot.enabled


def test_minimal_defaults(tmp_path):
    cfg = parse_config(base(tmp_path), tmp_path / "c.toml")
    assert cfg.restore.temp_vmid_base == 900000
    assert cfg.target.require_standalone is True
    assert cfg.vms[0].mode == "auto"
    assert cfg.vms[0].boot_timeout_s == 300
    assert "00000000" not in repr(cfg)


def test_is_temp_vmid(tmp_path):
    cfg = parse_config(base(tmp_path), tmp_path / "c.toml")
    assert cfg.is_temp_vmid(900105)
    assert not cfg.is_temp_vmid(105)
    assert not cfg.is_temp_vmid(900099)
    assert not cfg.is_temp_vmid(1_800_000)


def test_vm_target_default_for_unlisted(tmp_path):
    cfg = parse_config(base(tmp_path), tmp_path / "c.toml")
    t = cfg.vm_target(222)
    assert t.temp_vmid == 900222 and t.mode == "auto" and t.checks == ()
    with pytest.raises(ConfigError):
        cfg.vm_target(950000)


@pytest.mark.parametrize(
    ("mutate", "msg"),
    [
        (lambda r: r["target"].update(bogus=1), "unknown key"),
        (lambda r: r["target"].update(token_secret="inline"), "inline secrets"),
        (lambda r: r["target"].update(token_id="nobang"), "token_id"),
        (lambda r: r["target"].update(fingerprint="zz"), "fingerprint"),
        (lambda r: r["restore"].pop("isolated_bridge"), "isolated_bridge: required"),
        (lambda r: r["restore"].update(tag="Bad Tag"), "restore.tag"),
        (lambda r: r.update(vm=[{"vmid": 105}, {"vmid": 105}]), "duplicate"),
        (lambda r: r.update(vm=[{"vmid": 950000}]), "VMID"),
        (lambda r: r.update(vm=[{"vmid": 99}]), "VMID"),
        (lambda r: r.update(vm=[{"vmid": 105, "mode": "manual"}]), "manual"),
        (lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "nope"}]}]), "must be one of"),
        (lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "tcp_listen"}]}]), "port: required"),
        (lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "tcp_listen", "port": 70000}]}]), "1-65535"),
        (lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "http", "port": 80, "path": "x"}]}]), "start with /"),
        (lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "command", "argv": []}]}]), "argv"),
        (
            lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "command", "argv": ["x"], "stdout_regex": "("}]}]),
            "regex",
        ),
        (lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "script", "path": "missing.sh"}]}]), "not found"),
        (
            lambda r: r.update(vm=[{"vmid": 105, "check": [{"type": "systemd", "unit": "x", "extra": 1}]}]),
            "unknown key",
        ),
        (lambda r: r.update(vm=[]), "no [[vm]]"),
        (lambda r: r.update(notify={"email": {"enabled": True}}), "notify.email"),
        (lambda r: r.update(notify={"ntfy": {"enabled": True, "topic": "bad topic"}}), "topic"),
        (lambda r: r.update(node_shell={"mode": "ssh"}), "ssh_host"),
        (lambda r: r.update(screenshot={"enabled": True}), "node_shell"),
        (lambda r: r.update(node_shell={"mode": "local", "remote_dir": "rel"}), "absolute"),
        (lambda r: r.update(run={"selection": "some"}), "must be one of"),
    ],
)
def test_rejections(tmp_path, mutate, msg):
    raw = base(tmp_path)
    mutate(raw)
    with pytest.raises(ConfigError, match=msg.replace("[", r"\[").replace("]", r"\]")):
        parse_config(raw, tmp_path / "c.toml")


def test_world_readable_secret_rejected(tmp_path):
    raw = base(tmp_path)
    Path(raw["target"]["token_secret_file"]).chmod(0o644)
    with pytest.raises(ConfigError, match="world-readable"):
        parse_config(raw, tmp_path / "c.toml")


def test_secret_env(tmp_path, monkeypatch):
    raw = base(tmp_path)
    raw["target"] = {**raw["target"]}
    raw["target"].pop("token_secret_file")
    raw["target"]["token_secret_env"] = "PBV_TEST_TOKEN"
    monkeypatch.setenv("PBV_TEST_TOKEN", "s3cret")
    cfg = parse_config(raw, tmp_path / "c.toml")
    assert cfg.target.token_secret == "s3cret"
    monkeypatch.delenv("PBV_TEST_TOKEN")
    with pytest.raises(ConfigError, match="empty or unset"):
        parse_config(raw, tmp_path / "c.toml")


def test_script_paths_relative_to_config(tmp_path):
    (tmp_path / "s").mkdir()
    g = tmp_path / "s" / "g.sh"
    g.write_text("true\n")
    h = tmp_path / "s" / "h.sh"
    h.write_text("#!/bin/sh\ntrue\n")
    raw = base(
        tmp_path,
        vm=[
            {
                "vmid": 105,
                "check": [
                    {"type": "script", "path": "s/g.sh"},
                    {"type": "host_script", "path": "s/h.sh"},
                ],
            }
        ],
    )
    with pytest.raises(ConfigError, match="not executable"):
        parse_config(raw, tmp_path / "c.toml")
    os.chmod(h, 0o755)
    cfg = parse_config(raw, tmp_path / "c.toml")
    assert cfg.vms[0].checks[0].params["path"] == str(g.resolve())
    assert cfg.vms[0].checks[0].name == "script:g.sh"


def test_cmd_script_args_reject_metacharacters(tmp_path):
    (tmp_path / "x.cmd").write_text("@echo off\r\n")
    raw = base(tmp_path, vm=[{"vmid": 105, "check": [{"type": "script", "path": "x.cmd", "args": ["ok", "a&b"]}]}])
    with pytest.raises(ConfigError, match="metacharacters"):
        parse_config(raw, tmp_path / "c.toml")
    raw["vm"][0]["check"][0]["args"] = ["plain", "C:\\path\\ok"]
    assert parse_config(raw, tmp_path / "c.toml").vms[0].checks[0].params["args"] == ["plain", "C:\\path\\ok"]


def test_check_defaults_and_os(tmp_path):
    raw = base(
        tmp_path,
        run={"default_check_timeout_s": 42},
        vm=[
            {
                "vmid": 105,
                "check": [
                    {"type": "systemd", "unit": "nginx"},
                    {"type": "http", "port": 8080},
                    {"type": "command", "argv": ["true"], "os": "windows", "critical": False, "wait_s": 30},
                ],
            }
        ],
    )
    c = parse_config(raw, tmp_path / "c.toml").vms[0].checks
    assert c[0].only_os is OsFamily.LINUX and c[0].timeout_s == 42 and c[0].name == "systemd:nginx"
    assert c[1].params == {
        "port": 8080,
        "scheme": "http",
        "path": "/",
        "host": "127.0.0.1",
        "expect_status": None,
        "body_regex": "",
    }
    assert c[1].only_os is None
    assert c[2].only_os is OsFamily.WINDOWS and not c[2].critical and c[2].wait_s == 30
    assert c[2].params["expect_exit"] == [0] and c[2].params["warn_exit"] == []


def test_missing_and_bad_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")
    p = tmp_path / "bad.toml"
    p.write_text("[target\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(p)
