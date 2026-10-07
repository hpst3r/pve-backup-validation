"""Command-line entry point: wires config, PVE client, checks, notifiers and runner.

See docs/SPEC.md §8 for commands and exit codes.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Sequence

from pbv import __version__
from pbv.config import Config, load_config
from pbv.core import ConfigError, PbvError, PreflightError, RunReport, Status, report_to_dict

log = logging.getLogger("pbv")

EXIT_OK, EXIT_FAIL, EXIT_CONFIG, EXIT_CLEANUP, EXIT_LOCKED, EXIT_INTERRUPTED = 0, 1, 2, 3, 4, 130
DEFAULT_CONFIG = "/etc/pbv/config.toml"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pbv",
        description="Automated test restores of Proxmox Backup Server backups on a standalone restore node.",
    )
    p.add_argument("-c", "--config", default=os.environ.get("PBV_CONFIG", DEFAULT_CONFIG), help="config file (TOML)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    g.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")
    p.add_argument("--version", action="version", version=f"pbv {__version__}")
    sub = p.add_subparsers(dest="command")

    r = sub.add_parser("run", help="run the validation cycle (default)")
    r.add_argument("--vmid", type=int, action="append", help="only these source VMIDs (repeatable)")
    r.add_argument("--dry-run", action="store_true", help="preflight + backup resolution only; change nothing")
    r.add_argument(
        "--no-notify", action="store_true", help="do not send email/ntfy/telegram (JSON report still written)"
    )

    sub.add_parser("preflight", help="run safety guards against the restore node")
    lb = sub.add_parser("list-backups", help="show the newest backup per VM")
    lb.add_argument("--vmid", type=int, action="append")
    c = sub.add_parser("cleanup", help="destroy leftover temporary VMs on the restore node")
    c.add_argument("--include-kept", action="store_true", help="also destroy VMs kept with keep_on_failure")
    c.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    sub.add_parser("check-config", help="validate the config file and exit")
    sub.add_parser("notify-test", help="send a test notification through every enabled notifier")
    return p


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    root = logging.getLogger("pbv")
    root.setLevel(logging.DEBUG)
    if not any(getattr(h, "_pbv_cli", False) for h in root.handlers):
        h = logging.StreamHandler(sys.stderr)
        h._pbv_cli = True  # type: ignore[attr-defined]
        h.setLevel(level)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
        root.addHandler(h)


# ──────────────────────────────────────────────────────────────────────────────
# Wiring
# ──────────────────────────────────────────────────────────────────────────────


def build_api(cfg: Config):
    from pbv.pve import PveClient

    return PveClient.from_config(cfg.target)


def build_node_shell(cfg: Config):
    """NodeShellRunner for root@pam-only operations, or None when node_shell.mode is off."""
    from pbv.pve import NodeShellRunner

    return NodeShellRunner.from_config(cfg.node_shell, node=cfg.target.node)


def build_runner(
    cfg: Config,
    api,
    *,
    notify: bool = True,
    stop_flag=None,
    run_id: str | None = None,
    node_shell=None,
    guest_factory=None,
):
    """Construct the object graph. Factored out so E2E tests can inject fakes."""
    from dataclasses import replace

    from pbv.checks import CheckEngine
    from pbv.notify import build_notifiers
    from pbv.orchestrator import Runner, new_run_id
    from pbv.pve import ConsoleCapture, PveGuestAgent

    run_id = run_id or new_run_id()
    ncfg = cfg.notify
    if not notify:
        ncfg = replace(
            ncfg,
            email=replace(ncfg.email, enabled=False),
            ntfy=replace(ncfg.ntfy, enabled=False),
            telegram=replace(ncfg.telegram, enabled=False),
        )
    should_stop = stop_flag if stop_flag is not None else (lambda: False)
    engine = CheckEngine(cfg.config_dir, cfg.global_checks, should_stop=should_stop)
    notifiers = build_notifiers(ncfg)
    console = ConsoleCapture.from_config(node_shell, cfg.screenshot)
    return Runner(
        cfg,
        api,
        engine,
        notifiers,
        guest_factory=guest_factory or (lambda vmid: PveGuestAgent(api, vmid)),
        console=console,
        node_shell=node_shell,
        run_id=run_id,
        should_stop=should_stop,
        stop_flag=stop_flag,
        tool_version=__version__,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Commands
# ──────────────────────────────────────────────────────────────────────────────


def _fmt_age(ctime: int) -> str:
    h = (time.time() - ctime) / 3600
    return f"{h:.1f}h" if h < 48 else f"{h / 24:.1f}d"


def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    from pbv.orchestrator import RunLock, StopFlag, exit_code

    api = build_api(cfg)
    shell = build_node_shell(cfg)
    if args.dry_run:
        runner = build_runner(cfg, api, notify=False, node_shell=shell)
        from pbv.orchestrator import preflight

        try:
            steps = preflight(api, cfg, node_shell=shell)
        except PreflightError as exc:
            _print_steps(exc.steps)
            print(f"PREFLIGHT FAILED: {exc}")
            return EXIT_CONFIG
        _print_steps(steps)
        for target, ref in runner.plan(args.vmid):
            if ref is None:
                print(f"  {target.vmid:>6} -> {target.temp_vmid}: NO BACKUP")
            else:
                print(
                    f"  {target.vmid:>6} -> {target.temp_vmid}: {ref.volid} age={_fmt_age(ref.ctime)} "
                    f"size={ref.size / 2**30:.1f}GiB mode={target.mode} checks={len(target.checks)}"
                )
        print("dry run: nothing was created")
        return EXIT_OK

    stop = StopFlag()
    try:
        with RunLock(cfg.run.lock_file):
            stop.install()
            try:
                runner = build_runner(cfg, api, notify=not args.no_notify, stop_flag=stop, node_shell=shell)
                report = runner.run(args.vmid)
            finally:
                stop.uninstall()
    except PbvError as exc:
        if exc.code == "LOCKED":
            log.error("another pbv run is in progress (%s)", cfg.run.lock_file)
            return EXIT_LOCKED
        raise
    _print_summary(report)
    return exit_code(report, fail_on_warn=cfg.run.fail_on_warn)


def _print_steps(steps) -> None:
    for s in steps:
        mark = {"pass": "ok ", "warn": "WRN", "skipped": " - "}.get(s.status.value, "ERR")
        print(f"[{mark}] {s.name:<16} {s.message}")


def _print_summary(report: RunReport) -> None:
    c = report.counts
    print(
        f"pbv run {report.run_id} on {report.target_node}: {report.status.value.upper()} "
        f"({c['pass']} pass, {c['warn']} warn, {c['fail']} fail, {c['error']} error) in {report.duration_s:.0f}s"
    )
    for vm in report.vms:
        extra = f" {vm.failure_code}: {vm.failure_message}" if vm.failure_code else ""
        print(f"  {vm.vmid:>6} {vm.name:<24} {vm.status.value.upper():<7}{extra}")
        if not vm.cleanup_ok:
            print(f"         MANUAL CLEANUP REQUIRED: VM {vm.temp_vmid} on {report.target_node}")
    for e in report.sweep_failures:
        print(f"  LEFTOVER NOT REMOVED: {e}")
    for e in report.notify_errors:
        print(f"  notify error: {e}")


def cmd_preflight(cfg: Config, args: argparse.Namespace) -> int:
    from pbv.orchestrator import preflight

    try:
        steps = preflight(build_api(cfg), cfg, node_shell=build_node_shell(cfg))
    except PreflightError as exc:
        _print_steps(exc.steps)
        print(f"PREFLIGHT FAILED: {exc}")
        return EXIT_CONFIG
    _print_steps(steps)
    bad = [s for s in steps if s.status in (Status.FAIL, Status.ERROR)]
    return EXIT_CONFIG if bad else EXIT_OK


def cmd_list_backups(cfg: Config, args: argparse.Namespace) -> int:
    api = build_api(cfg)
    backups = api.list_backups(cfg.restore.backup_storage)
    newest: dict[int, object] = {}
    for b in backups:
        if b.vmid not in newest or b.ctime > newest[b.vmid].ctime:  # type: ignore[attr-defined]
            newest[b.vmid] = b
    wanted = set(args.vmid or []) or None
    for vmid in sorted(newest):
        if wanted and vmid not in wanted:
            continue
        b = newest[vmid]
        flags = []
        if b.verified is not None:  # type: ignore[attr-defined]
            flags.append("verified" if b.verified else "VERIFY-FAILED")  # type: ignore[attr-defined]
        if b.encrypted:  # type: ignore[attr-defined]
            flags.append("encrypted")
        print(f"{vmid:>6}  {b.volid}  age={_fmt_age(b.ctime)}  size={b.size / 2**30:.1f}GiB  {' '.join(flags)}")  # type: ignore[attr-defined]
    for vmid in sorted(wanted or ()):
        if vmid not in newest:
            print(f"{vmid:>6}  NO BACKUP on {cfg.restore.backup_storage}")
    return EXIT_OK


def cmd_cleanup(cfg: Config, args: argparse.Namespace) -> int:
    from pbv.orchestrator import RunLock

    api = build_api(cfg)
    if not args.yes:
        if not sys.stdin.isatty():
            print("refusing to clean up non-interactively without --yes", file=sys.stderr)
            return EXIT_CONFIG
        ans = input(f"Destroy pbv temporary VMs on {cfg.target.node}? [y/N] ")
        if ans.strip().lower() not in ("y", "yes"):
            return EXIT_OK
    try:
        with RunLock(cfg.run.lock_file):
            runner = build_runner(cfg, api, notify=False, node_shell=build_node_shell(cfg))
            swept = runner.sweep(include_kept=args.include_kept)
            for f in runner.last_sweep_failures:
                print(f"failed: {f}")
    except PbvError as exc:
        if exc.code == "LOCKED":
            log.error("another pbv run is in progress (%s)", cfg.run.lock_file)
            return EXIT_LOCKED
        raise
    print(f"destroyed: {', '.join(map(str, swept)) or 'nothing'}")
    remaining = [v["vmid"] for v in api.list_vms() if cfg.is_temp_vmid(int(v["vmid"]))]
    if remaining:
        print(f"still present in temp range: {', '.join(map(str, remaining))}")
        return EXIT_CLEANUP
    return EXIT_OK


def cmd_check_config(cfg: Config, args: argparse.Namespace) -> int:
    n_checks = sum(len(v.checks) for v in cfg.vms)
    enabled = [n for n in ("email", "ntfy", "json", "telegram") if getattr(cfg.notify, n).enabled]
    print(
        f"config OK: {cfg.path}\n  target {cfg.target.node} ({cfg.target.host}:{cfg.target.port})\n"
        f"  {len(cfg.vms)} VM(s), {n_checks} VM check(s), {len(cfg.global_checks)} global check(s)\n"
        f"  selection={cfg.run.selection} notifiers={','.join(enabled) or 'none'} screenshots={cfg.screenshot.mode}"
    )
    return EXIT_OK


def cmd_notify_test(cfg: Config, args: argparse.Namespace) -> int:
    from pbv.notify import build_notifiers, send_test

    results = send_test(build_notifiers(cfg.notify), node=cfg.target.node)
    print(json.dumps(results, indent=2))
    return EXIT_OK if all(v == "ok" for v in results.values()) else EXIT_FAIL


COMMANDS = {
    "run": cmd_run,
    "preflight": cmd_preflight,
    "list-backups": cmd_list_backups,
    "cleanup": cmd_cleanup,
    "check-config": cmd_check_config,
    "notify-test": cmd_notify_test,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args([*(argv if argv is not None else sys.argv[1:]), "run"])
    _setup_logging(args.verbose, args.quiet)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        return COMMANDS[args.command](cfg, args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except PreflightError as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except PbvError as exc:
        print(f"error [{exc.code}]: {exc}", file=sys.stderr)
        log.debug("details", exc_info=True)
        return EXIT_FAIL


def _report_json(report: RunReport) -> str:  # used by tests / debugging
    return json.dumps(report_to_dict(report), indent=2, sort_keys=True)


if __name__ == "__main__":
    sys.exit(main())
