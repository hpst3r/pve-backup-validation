"""NodeShellRunner with a fake ``run`` that emulates qm/ssh/scp/converters (no real processes)."""

from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from pbv.config import NodeShellConfig
from pbv.core import ConfigError, NodeShell, PbvError
from pbv.pve import NodeShellRunner
from pbv.pve.nodeshell import PNG_MAGIC

VMID = 900105
TS = 1760000000.0
PPM = b"P6\n1 1\n255\n\x00\x00\x00"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]


class FakeRun:
    """Records calls; emulates the node's filesystem under ``remote_root`` (ssh) or the real one (local).

    ``fail`` maps a key to a return code or an exception. Keys: the local tool
    name (``qm``, ``scp``, ``pnmtopng``, ``convert``), ``ssh`` (every ssh
    call), or ``ssh:<remote program>`` (e.g. ``ssh:rm``).
    ``png_ok``: ``screendump -f png`` works; otherwise QEMU prints an error and writes nothing.
    """

    def __init__(
        self,
        remote_root: Path | None = None,
        *,
        fail: dict[str, Any] | None = None,
        png_ok: bool = True,
        stderr: bytes = b"Permission denied (publickey).",
    ) -> None:
        self.remote_root = remote_root
        self.fail = fail or {}
        self.png_ok = png_ok
        self.stderr = stderr
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    @property
    def argvs(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(argv), kw))
        assert kw["timeout"] > 0
        assert kw.get("check") is False
        tool = Path(argv[0]).name
        keys = [tool]
        if tool == "ssh":
            keys.append("ssh:" + shlex.split(argv[-1])[0])
        for key in keys:
            err = self.fail.get(key)
            if isinstance(err, BaseException):
                raise err
            if err is not None:
                return subprocess.CompletedProcess(argv, err, b"", b"some noise\n" + self.stderr + b"\n")
        out = b""
        if tool == "qm":
            out = self._qm(argv, kw, Path("/"))
        elif tool == "ssh":
            for words in _commands(argv[-1]):
                if words[0] == "qm" and words[1] != "monitor":
                    continue
                assert self.remote_root is not None, "this ssh command touches the node's filesystem"
                if words[0] == "qm":
                    out = self._qm(words, kw, self.remote_root)
                elif words[0] == "mkdir":
                    _under(self.remote_root, words[-1]).mkdir(parents=True, exist_ok=True)
                elif words[0] == "rm":
                    _under(self.remote_root, words[-1]).unlink(missing_ok=True)
        elif tool == "scp":
            assert self.remote_root is not None
            src = _under(self.remote_root, argv[-2].split(":", 1)[1])
            if not src.exists():
                return subprocess.CompletedProcess(argv, 1, b"", b"scp: No such file or directory\n")
            Path(argv[-1]).write_bytes(src.read_bytes())
        elif tool == "pnmtopng":
            kw["stdout"].write(PNG_MAGIC + b"converted")
        elif tool == "convert":
            Path(argv[-1]).write_bytes(PNG_MAGIC + b"converted")
        return subprocess.CompletedProcess(argv, 0, out, b"")

    def _qm(self, words: list[str], kw: dict[str, Any], root: Path) -> bytes:
        if words[1] != "monitor":
            return b""
        hmp = kw["input"].decode()
        assert hmp.endswith("\n")
        parts = hmp.split()
        assert parts[0] == "screendump"
        target = _under(root, parts[1]) if root != Path("/") else Path(parts[1])
        if parts[2:] == ["-f", "png"]:
            if not self.png_ok:
                return b"qm> screendump: invalid option -f\n"
            target.write_bytes(PNG_MAGIC + b"img")
        else:
            target.write_bytes(PPM)
        return b"qm> \n"


def _commands(remote: str) -> list[list[str]]:
    """Split a remote shell string into its ``&&``-joined commands."""
    cmds: list[list[str]] = [[]]
    for word in shlex.split(remote):
        if word == "&&":
            cmds.append([])
        else:
            cmds[-1].append(word)
    return cmds


def _under(root: Path, path: str) -> Path:
    return Path(str(root) + path)


def _which(available: set[str]) -> Any:
    return lambda name: f"/usr/bin/{name}" if name in available else None


def local(tmp_path: Path, run: FakeRun, *, euid: int = 0, tools: set[str] | None = None) -> NodeShellRunner:
    cfg = NodeShellConfig(mode="local", remote_dir=str(tmp_path / "node" / "dump"), timeout_s=7)
    return NodeShellRunner(
        cfg,
        node="pve1",
        run=run,
        which=_which({"qm"} if tools is None else tools),
        geteuid=lambda: euid,
        wall_clock=lambda: TS,
    )


def ssh(run: FakeRun, *, tools: set[str] | None = None, **cfg_kw: Any) -> NodeShellRunner:
    fields: dict[str, Any] = {"mode": "ssh", "ssh_host": "pve1.lan", "remote_dir": "/var/lib/pbv/dump", "timeout_s": 7}
    fields.update(cfg_kw)
    return NodeShellRunner(
        NodeShellConfig(**fields), node="pve1", run=run, which=_which(tools or set()), wall_clock=lambda: TS
    )


def remote_of(argv: list[str]) -> str:
    """The remote command string of an ssh argv (after ``--``)."""
    assert argv[0] == "ssh"
    assert argv[-2] == "--"
    return argv[-1]


# ── construction ──────────────────────────────────────────────────────────────


def test_protocol(tmp_path: Path) -> None:
    assert isinstance(local(tmp_path, FakeRun()), NodeShell)


def test_from_config_none_when_off() -> None:
    assert NodeShellRunner.from_config(NodeShellConfig(mode="off"), node="pve1") is None
    shell = NodeShellRunner.from_config(NodeShellConfig(mode="ssh", ssh_host="h"), node="pve1", run=FakeRun())
    assert isinstance(shell, NodeShellRunner)


@pytest.mark.parametrize(
    ("cfg", "match"),
    [
        (NodeShellConfig(mode="off"), "node_shell.mode"),
        (NodeShellConfig(mode="telnet"), "node_shell.mode"),
        (NodeShellConfig(mode="local", remote_dir="relative/dir"), "remote_dir"),
        (NodeShellConfig(mode="local", remote_dir="/tmp/a b"), "remote_dir"),
        (NodeShellConfig(mode="local", remote_dir="/tmp/a\n"), "remote_dir"),
        (NodeShellConfig(mode="ssh", ssh_host="h", remote_dir="/tmp/$(id)"), "remote_dir"),
        (NodeShellConfig(mode="local", timeout_s=0), "timeout_s"),
    ],
)
def test_constructor_validation(cfg: NodeShellConfig, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        NodeShellRunner(cfg, node="pve1")


def test_ssh_host_defaults_to_node() -> None:
    run = FakeRun()
    shell = NodeShellRunner(NodeShellConfig(mode="ssh"), node="pve9", run=run)
    assert shell.probe() == "ssh root@pve9: ok"
    with pytest.raises(ConfigError, match="ssh_host"):
        NodeShellRunner(NodeShellConfig(mode="ssh"), node="")


# ── argv shape and quoting ────────────────────────────────────────────────────


def test_ssh_argv_full_options() -> None:
    run = FakeRun()
    shell = ssh(run, ssh_user="admin", ssh_port=2222, ssh_key_file="/k/id_ed25519", ssh_known_hosts_file="/k/known")
    shell.qm_set(VMID, {"onboot": "0"}, [])
    assert run.argvs == [
        [
            "ssh",
            *SSH_OPTS,
            "-p",
            "2222",
            "-i",
            "/k/id_ed25519",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "UserKnownHostsFile=/k/known",
            "admin@pve1.lan",
            "--",
            "qm set 900105 --onboot 0",
        ]
    ]
    _, kw = run.calls[0]
    assert kw["capture_output"] is True
    assert kw["timeout"] == 7


def test_ssh_argv_without_optional_files() -> None:
    run = FakeRun()
    ssh(run).qm_set(VMID, {}, ["hostpci0"])
    assert run.argvs == [["ssh", *SSH_OPTS, "-p", "22", "root@pve1.lan", "--", "qm set 900105 --delete hostpci0"]]


def test_hostile_values_are_single_quoted_tokens() -> None:
    run = FakeRun()
    hostile = {
        "description": "$(rm -rf /); `reboot` && echo pwned > /etc/x\n'quoted' \"dq\"",
        "args": "-device foo,bar=1 | nc evil 1",
        "serial0": "socket",
    }
    ssh(run).qm_set(VMID, hostile, ["usb1", "hostpci0"])
    expected = ["qm", "set", "900105"]
    for k in sorted(hostile):
        expected += [f"--{k}", hostile[k]]
    expected += ["--delete", "hostpci0,usb1"]
    assert shlex.split(remote_of(run.argvs[0])) == expected


def test_local_qm_set_runs_qm_directly(tmp_path: Path) -> None:
    run = FakeRun()
    local(tmp_path, run).qm_set(VMID, {"tags": "a;b", "args": "$(x)"}, ["protection", "hostpci0"])
    assert run.argvs == [["qm", "set", "900105", "--args", "$(x)", "--tags", "a;b", "--delete", "hostpci0,protection"]]


def test_qm_set_noop_when_empty(tmp_path: Path) -> None:
    run = FakeRun()
    local(tmp_path, run).qm_set(VMID, {}, [])
    assert run.calls == []


@pytest.mark.parametrize(
    ("set_", "delete", "match"),
    [
        ({"--evil": "x"}, [], "invalid config key"),
        ({"Bad": "x"}, [], "invalid config key"),
        ({"a b": "x"}, [], "invalid config key"),
        ({}, ["hostpci0,usb0"], "invalid config key"),
        ({}, ["x;rm"], "invalid config key"),
        ({"onboot\n": "0"}, [], "invalid config key"),
        ({"net0": 5}, [], "must be a string"),
    ],
)
def test_qm_set_rejects_bad_keys(tmp_path: Path, set_: dict[str, Any], delete: list[str], match: str) -> None:
    run = FakeRun()
    with pytest.raises(PbvError, match=match) as ei:
        local(tmp_path, run).qm_set(VMID, set_, delete)
    assert ei.value.code == "NODE_SHELL_FAIL"
    assert run.calls == []


@pytest.mark.parametrize("vmid", ["900105", 900105.0, True])
def test_qm_set_rejects_non_int_vmid(tmp_path: Path, vmid: Any) -> None:
    with pytest.raises(PbvError, match="vmid must be an int") as ei:
        local(tmp_path, FakeRun()).qm_set(vmid, {"onboot": "0"}, [])
    assert ei.value.code == "NODE_SHELL_FAIL"


# ── qm_set failures ───────────────────────────────────────────────────────────


def test_qm_set_nonzero_exit_message_has_last_stderr_line() -> None:
    long_err = b"400 Parameter verification failed. " + b"x" * 400
    run = FakeRun(fail={"ssh": 2}, stderr=long_err)
    with pytest.raises(PbvError) as ei:
        ssh(run).qm_set(VMID, {"onboot": "0"}, [])
    assert ei.value.code == "NODE_SHELL_FAIL"
    msg = str(ei.value)
    assert msg.startswith("node shell: qm set 900105 failed (exit 2): 400 Parameter verification failed. x")
    assert "some noise" not in msg
    tail = msg.split(": ", 2)[2]
    assert len(tail) == 200


def test_qm_set_failure_without_stderr(tmp_path: Path) -> None:
    run = FakeRun(fail={"qm": 25}, stderr=b"")
    with pytest.raises(PbvError, match=r"qm set 900105 failed \(exit 25\): some noise"):
        local(tmp_path, run).qm_set(VMID, {"onboot": "0"}, [])


@pytest.mark.parametrize(
    ("err", "match"),
    [
        (subprocess.TimeoutExpired(["qm"], 7), r"node shell: qm set 900105 timed out after 7s"),
        (FileNotFoundError(2, "No such file or directory", "qm"), r"node shell: qm set 900105 could not run"),
    ],
)
def test_qm_set_timeout_and_oserror(tmp_path: Path, err: BaseException, match: str) -> None:
    with pytest.raises(PbvError, match=match) as ei:
        local(tmp_path, FakeRun(fail={"qm": err})).qm_set(VMID, {"onboot": "0"}, [])
    assert ei.value.code == "NODE_SHELL_FAIL"


# ── unlock / sysctl ───────────────────────────────────────────────────────────


class Stdout(FakeRun):
    """FakeRun whose successful commands print ``out``."""

    def __init__(self, out: bytes, **kw: Any) -> None:
        super().__init__(**kw)
        self.out = out

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        proc = super().__call__(argv, **kw)
        return proc if proc.returncode else subprocess.CompletedProcess(argv, 0, self.out, b"")


def test_unlock_local_and_ssh(tmp_path: Path) -> None:
    run = FakeRun()
    local(tmp_path, run).unlock(VMID)
    ssh(run, ssh_port=2222).unlock(VMID)
    assert run.argvs[0] == ["qm", "unlock", "900105"]
    assert run.argvs[1][:-2] == ["ssh", *SSH_OPTS, "-p", "2222", "root@pve1.lan"]
    assert shlex.split(remote_of(run.argvs[1])) == ["qm", "unlock", "900105"]
    assert run.calls[1][1]["timeout"] == 7


@pytest.mark.parametrize("vmid", ["900105; reboot", 900105.0, True])
def test_unlock_rejects_non_int_vmid(tmp_path: Path, vmid: Any) -> None:
    run = FakeRun()
    with pytest.raises(PbvError, match="vmid must be an int") as ei:
        local(tmp_path, run).unlock(vmid)
    assert ei.value.code == "NODE_SHELL_FAIL"
    assert run.calls == []


@pytest.mark.parametrize(
    ("fail", "match"),
    [
        (2, r"node shell: qm unlock 900105 failed \(exit 2\): Permission denied"),
        (subprocess.TimeoutExpired(["ssh"], 7), r"node shell: qm unlock 900105 timed out after 7s"),
        (FileNotFoundError(2, "No such file or directory", "ssh"), r"qm unlock 900105 could not run"),
    ],
)
def test_unlock_failures(fail: Any, match: str) -> None:
    with pytest.raises(PbvError, match=match) as ei:
        ssh(FakeRun(fail={"ssh": fail})).unlock(VMID)
    assert ei.value.code == "NODE_SHELL_FAIL"


def test_sysctl_hostname_local_and_ssh(tmp_path: Path) -> None:
    run = Stdout(b"pve1\n", remote_root=tmp_path)
    assert local(tmp_path, run).sysctl("kernel.hostname") == "pve1"
    assert ssh(run).sysctl("kernel.hostname") == "pve1"
    assert run.argvs[0] == ["sysctl", "-n", "kernel.hostname"]
    assert shlex.split(remote_of(run.argvs[1])) == ["sysctl", "-n", "kernel.hostname"]
    assert run.calls[1][1]["capture_output"] is True


def test_sysctl_str_stdout_and_other_keys(tmp_path: Path) -> None:
    run = Stdout(" 1 \n")  # type: ignore[arg-type]  # text-mode run
    assert local(tmp_path, run).sysctl("net.ipv4.ip_forward") == "1"
    assert local(tmp_path, run).sysctl("net.ipv6.conf.vmbr0-1.disable_ipv6") == "1"


@pytest.mark.parametrize(
    "key", ["", "kernel.hostname; reboot", "Kernel.Hostname", "-a", "a b", "$(id)", "a/b", "x\n", 5]
)
def test_sysctl_rejects_bad_key(tmp_path: Path, key: Any) -> None:
    run = FakeRun()
    with pytest.raises(PbvError, match="invalid sysctl key") as ei:
        local(tmp_path, run).sysctl(key)
    assert ei.value.code == "NODE_SHELL_FAIL"
    assert run.calls == []


def test_sysctl_failure() -> None:
    run = FakeRun(fail={"ssh:sysctl": 255}, stderr=b"sysctl: cannot stat /proc/sys/x/y: No such file or directory")
    with pytest.raises(PbvError, match=r"node shell: sysctl x.y failed \(exit 255\): sysctl: cannot stat") as ei:
        ssh(run).sysctl("x.y")
    assert ei.value.code == "NODE_SHELL_FAIL"


# ── probe ─────────────────────────────────────────────────────────────────────


def test_probe_local_ok(tmp_path: Path) -> None:
    run = FakeRun()
    assert local(tmp_path, run).probe() == "local root on pve1: ok"
    assert run.calls == []


def test_probe_local_not_root(tmp_path: Path) -> None:
    with pytest.raises(PbvError, match=r"pbv must run as root on the restore node for node_shell\.mode = local") as ei:
        local(tmp_path, FakeRun(), euid=1000).probe()
    assert ei.value.code == "NODE_SHELL_FAIL"


def test_probe_local_qm_missing(tmp_path: Path) -> None:
    with pytest.raises(PbvError, match=r"qm not found: is this a PVE node\?") as ei:
        local(tmp_path, FakeRun(), tools=set()).probe()
    assert ei.value.code == "NODE_SHELL_FAIL"


def test_probe_ssh_ok() -> None:
    run = FakeRun()
    assert ssh(run).probe() == "ssh root@pve1.lan: ok"
    assert remote_of(run.argvs[0]) == "qm list"


def test_probe_ssh_exit_255() -> None:
    run = FakeRun(fail={"ssh": 255}, stderr=b"root@pve1.lan: Permission denied (publickey).")
    with pytest.raises(PbvError) as ei:
        ssh(run).probe()
    assert ei.value.code == "NODE_SHELL_FAIL"
    assert str(ei.value) == (
        "node shell: ssh root@pve1.lan failed (exit 255): root@pve1.lan: Permission denied (publickey)."
    )


def test_probe_ssh_timeout() -> None:
    run = FakeRun(fail={"ssh": subprocess.TimeoutExpired(["ssh"], 7)})
    with pytest.raises(PbvError, match="timed out after 7s"):
        ssh(run).probe()


def test_repr_has_no_surprises() -> None:
    assert repr(ssh(FakeRun(), ssh_port=2222)) == "NodeShellRunner(mode='ssh', node='root@pve1.lan:2222')"


# ── screendump: local ─────────────────────────────────────────────────────────


def test_local_png(tmp_path: Path) -> None:
    run = FakeRun()
    shell = local(tmp_path, run)
    out = shell.screendump(VMID, tmp_path / "out" / "boot")
    assert out == tmp_path / "out" / "boot.png"
    assert out.read_bytes().startswith(PNG_MAGIC)
    remote = f"{tmp_path}/node/dump/pbv-{VMID}-{int(TS)}.png"
    argv, kw = run.calls[0]
    assert argv == ["qm", "monitor", str(VMID)]
    assert kw["input"] == f"screendump {remote} -f png\n".encode()
    assert not Path(remote).exists()  # moved, not copied


def test_local_ppm_fallback_with_pnmtopng(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(png_ok=False)
    caplog.set_level(logging.INFO, "pbv.pve")
    out = local(tmp_path, run, tools={"qm", "pnmtopng", "convert"}).screendump(VMID, tmp_path / "boot")
    assert out == tmp_path / "boot.png"
    assert out.read_bytes() == PNG_MAGIC + b"converted"
    assert not (tmp_path / "boot.ppm").exists()
    assert run.calls[1][1]["input"] == f"screendump {tmp_path}/node/dump/pbv-{VMID}-{int(TS)}.ppm\n".encode()
    assert run.argvs[2] == ["/usr/bin/pnmtopng", str(tmp_path / "boot.ppm")]
    assert "SCREENSHOT_PNG_FAIL" in caplog.text
    assert "converted from PPM" in caplog.text


def test_local_ppm_fallback_with_convert(tmp_path: Path) -> None:
    run = FakeRun(png_ok=False)
    out = local(tmp_path, run, tools={"qm", "convert"}).screendump(VMID, tmp_path / "boot")
    assert out == tmp_path / "boot.png"
    assert run.argvs[-1] == ["/usr/bin/convert", str(tmp_path / "boot.ppm"), str(tmp_path / "boot.png")]


def test_local_png_magic_wrong_triggers_ppm_retry(tmp_path: Path) -> None:
    class GarbagePng(FakeRun):
        def _qm(self, words: list[str], kw: dict[str, Any], root: Path) -> bytes:
            parts = kw["input"].decode().split()
            Path(parts[1]).write_bytes(b"garbage" if parts[2:] else PPM)
            return b""

    out = local(tmp_path, GarbagePng(), tools={"qm", "convert"}).screendump(VMID, tmp_path / "boot")
    assert out == tmp_path / "boot.png"


def test_ppm_without_converter_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    out = local(tmp_path, FakeRun(png_ok=False)).screendump(VMID, tmp_path / "boot")
    assert out is None
    assert "neither pnmtopng nor convert is installed" in caplog.text
    assert (tmp_path / "boot.ppm").exists()  # kept for inspection
    assert not (tmp_path / "boot.png").exists()


def test_converter_failure_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(png_ok=False, fail={"pnmtopng": 1}, stderr=b"pnmtopng: bad magic")
    assert local(tmp_path, run, tools={"qm", "pnmtopng"}).screendump(VMID, tmp_path / "boot") is None
    assert "pnmtopng exited 1: pnmtopng: bad magic" in caplog.text


def test_local_nothing_written_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    class Silent(FakeRun):
        def _qm(self, words: list[str], kw: dict[str, Any], root: Path) -> bytes:
            return b"qm> Could not open '/x': Permission denied\n"

    assert local(tmp_path, Silent()).screendump(VMID, tmp_path / "boot") is None
    assert "SCREENSHOT_FAIL" in caplog.text
    assert "was not created" in caplog.text


def test_local_qm_monitor_failure_returns_none(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(fail={"qm": 2}, stderr=b"VM 900105 not running")
    assert local(tmp_path, run).screendump(VMID, tmp_path / "boot") is None
    assert "qm monitor 900105 failed (exit 2): VM 900105 not running" in caplog.text
    assert len(run.calls) == 2  # png attempt + ppm retry


def test_unexpected_exception_never_raises(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    class Boom(FakeRun):
        def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
            raise RuntimeError("kaboom")

    assert local(tmp_path, Boom()).screendump(VMID, tmp_path / "boot") is None
    assert "RuntimeError: kaboom" in caplog.text


def test_unwritable_dest_never_raises(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert local(tmp_path, FakeRun()).screendump(VMID, blocker / "sub" / "boot") is None


# ── screendump: ssh ───────────────────────────────────────────────────────────


@pytest.fixture
def remote_root(tmp_path: Path) -> Path:
    root = tmp_path / "node"
    root.mkdir()
    return root


def test_ssh_png(tmp_path: Path, remote_root: Path) -> None:
    run = FakeRun(remote_root)
    shell = ssh(run, ssh_port=2222, ssh_key_file="/k/id", ssh_known_hosts_file="/k/kh")
    out = shell.screendump(VMID, tmp_path / "boot")
    assert out == tmp_path / "boot.png"
    assert out.read_bytes().startswith(PNG_MAGIC)
    remote = f"/var/lib/pbv/dump/pbv-{VMID}-{int(TS)}.png"
    opts = ["-i", "/k/id", "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=/k/kh"]
    monitor, scp, rm = run.calls
    assert monitor[0] == ["ssh", *SSH_OPTS, "-p", "2222", *opts, "root@pve1.lan", "--", monitor[0][-1]]
    assert monitor[0][-1] == f"mkdir -p /var/lib/pbv/dump && qm monitor {VMID}"
    assert monitor[1]["input"] == f"screendump {remote} -f png\n".encode()
    assert scp[0] == ["scp", *SSH_OPTS, "-P", "2222", *opts, f"root@pve1.lan:{remote}", str(out)]
    assert shlex.split(remote_of(rm[0])) == ["rm", "-f", "--", remote]
    assert not _under(remote_root, remote).exists()


def test_ssh_ppm_fallback(tmp_path: Path, remote_root: Path) -> None:
    run = FakeRun(remote_root, png_ok=False)
    out = ssh(run, tools={"pnmtopng"}).screendump(VMID, tmp_path / "boot")
    assert out == tmp_path / "boot.png"
    assert out.read_bytes() == PNG_MAGIC + b"converted"
    tools = [a[0] if a[0] != "ssh" else "ssh " + shlex.split(a[-1])[-3 if "&&" in a[-1] else 0] for a in run.argvs]
    # png: monitor, scp (fails: nothing written), rm; ppm: monitor, scp, rm; convert
    assert tools == ["ssh qm", "scp", "ssh rm", "ssh qm", "scp", "ssh rm", "/usr/bin/pnmtopng"]
    assert list(remote_root.rglob("*.p?m")) == []


def test_ssh_ppm_converter_missing(tmp_path: Path, remote_root: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert ssh(FakeRun(remote_root, png_ok=False)).screendump(VMID, tmp_path / "boot") is None
    assert "neither pnmtopng nor convert is installed" in caplog.text


def test_ssh_scp_failure_returns_none_and_still_removes(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(tmp_path, fail={"scp": 1})
    assert ssh(run).screendump(VMID, tmp_path / "boot") is None
    rms = [a for a in run.argvs if a[0] == "ssh" and a[-1].startswith("rm ")]
    assert len(rms) == 2  # one per attempt (png, ppm)
    assert "scp exited 1: Permission denied (publickey)." in caplog.text


def test_ssh_remote_cleanup_failure_is_logged(
    tmp_path: Path, remote_root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run = FakeRun(remote_root, fail={"ssh:rm": 1})
    out = ssh(run).screendump(VMID, tmp_path / "boot")
    assert out == tmp_path / "boot.png"  # cleanup failure does not fail the capture
    assert "SCREENSHOT_REMOTE_CLEANUP_FAIL" in caplog.text


@pytest.mark.parametrize(
    "err", [FileNotFoundError(2, "No such file or directory", "ssh"), subprocess.TimeoutExpired(["ssh"], 7)]
)
def test_ssh_missing_or_timeout(tmp_path: Path, err: BaseException, caplog: pytest.LogCaptureFixture) -> None:
    assert ssh(FakeRun(tmp_path, fail={"ssh": err})).screendump(VMID, tmp_path / "boot") is None
    assert "SCREENSHOT_FAIL" in caplog.text


def test_ssh_ipv6_host_is_bracketed_for_scp(tmp_path: Path, remote_root: Path) -> None:
    run = FakeRun(remote_root)
    # FakeRun splits scp source on the first ':' after the bracketed host
    run_scp: list[str] = []

    def spy(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "scp":
            run_scp.extend(argv)
            argv = [*argv[:-2], "root@h:" + argv[-2].split("]:", 1)[1], argv[-1]]
        return run(argv, **kw)

    shell = NodeShellRunner(
        NodeShellConfig(mode="ssh", ssh_host="fd00::1", remote_dir="/var/lib/pbv/dump"),
        node="pve1",
        run=spy,
        wall_clock=lambda: TS,
    )
    assert shell.screendump(VMID, tmp_path / "boot") == tmp_path / "boot.png"
    assert run_scp[-2] == f"root@[fd00::1]:/var/lib/pbv/dump/pbv-{VMID}-{int(TS)}.png"
    assert run.argvs[0][-3] == "root@fd00::1"
