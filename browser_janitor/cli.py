from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .console import print_extension_summary, print_scan_summary
from .extensions import scan_extensions
from .performance import apply_profile, audit_performance, benchmark, list_backups, restore_backup, take_snapshot
from .report import extensions_to_json, human_size, to_json, write_report
from .scanner import remove_candidate, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="browser-janitor",
        description="Safely scan and clean regenerable browser cache files.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Show safe cleanup candidates.")
    scan_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    scan_cmd.add_argument("--report", type=Path, help="Write a report to this path.")
    scan_cmd.add_argument("--html", action="store_true", help="Use HTML when writing --report.")

    clean_cmd = sub.add_parser("clean", help="Clean safe cache targets.")
    clean_cmd.add_argument("--apply", action="store_true", help="Actually delete safe cache targets.")
    clean_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON summary.")
    clean_cmd.add_argument("--report", type=Path, help="Write a report before cleaning.")
    clean_cmd.add_argument("--html", action="store_true", help="Use HTML when writing --report.")

    ext_cmd = sub.add_parser("extensions", help="Audit installed browser extensions.")
    ext_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    doctor_cmd = sub.add_parser("doctor", help="Show browser cleanup and extension health summary.")
    doctor_cmd.add_argument("--report", type=Path, help="Write an HTML report to this path.")

    perf_cmd = sub.add_parser("perf", help="Audit browser RAM/FPS performance settings.")
    perf_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    opt_cmd = sub.add_parser("optimize", help="Apply a safe browser performance profile.")
    opt_cmd.add_argument("--profile", choices=["gaming", "low-ram", "balanced"], required=True)
    opt_cmd.add_argument("--apply", action="store_true", help="Write changes. Without this, only prints a plan.")

    bench_cmd = sub.add_parser("bench", help="Measure browser RAM/process usage before and after a short delay.")
    bench_cmd.add_argument("--delay", type=int, default=5, help="Seconds between snapshots.")
    bench_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    watch_cmd = sub.add_parser("watch", help="Watch browser RAM/process usage.")
    watch_cmd.add_argument("--interval", type=int, default=5, help="Refresh interval in seconds.")
    watch_cmd.add_argument("--ticks", type=int, default=0, help="Number of refreshes. 0 means until Ctrl+C.")

    restore_cmd = sub.add_parser("restore", help="List or restore Browser Janitor setting backups.")
    restore_cmd.add_argument("--list", action="store_true", help="List backups.")
    restore_cmd.add_argument("--index", type=int, help="Restore backup by list index.")
    restore_cmd.add_argument("--apply", action="store_true", help="Actually restore the selected backup.")

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    candidates = scan()
    if args.report:
        extensions = scan_extensions() if args.html else None
        write_report(args.report, candidates, "html" if args.html else "md", extensions)
    if args.json:
        print(to_json(candidates))
        return 0
    print_scan_summary(candidates)
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    candidates = scan()
    safe = [item for item in candidates if item.safe]
    total = sum(item.size_bytes for item in safe)

    if args.report:
        extensions = scan_extensions() if args.html else None
        write_report(args.report, candidates, "html" if args.html else "md", extensions)

    if not args.apply:
        message = (
            f"Dry run: {len(safe)} safe targets, {human_size(total)} reclaimable. "
            "Run with --apply to clean."
        )
        if args.json:
            print(to_json(safe))
        else:
            print(message)
        return 0

    removed = []
    failed = []
    for item in safe:
        try:
            remove_candidate(item)
            removed.append(item)
        except OSError as exc:
            failed.append((item, str(exc)))

    if args.json:
        print(
            to_json(removed)
        )
    else:
        print(f"Cleaned {len(removed)} targets, reclaimed up to {human_size(total)}.")
        if failed:
            print(f"Skipped {len(failed)} locked targets:")
            for item, error in failed:
                print(f"- {item.path}: {error}", file=sys.stderr)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "clean":
        return cmd_clean(args)
    if args.command == "extensions":
        extensions = scan_extensions()
        if args.json:
            print(extensions_to_json(extensions))
        else:
            print_extension_summary(extensions)
        return 0
    if args.command == "doctor":
        candidates = scan()
        extensions = scan_extensions()
        print_scan_summary(candidates)
        print()
        print_extension_summary(extensions)
        if args.report:
            write_report(args.report, candidates, "html", extensions)
            print()
            print(f"HTML report written to: {args.report}")
        return 0
    if args.command == "perf":
        usage, findings = audit_performance()
        if args.json:
            import json

            print(
                json.dumps(
                    {
                        "usage": [item.__dict__ for item in usage],
                        "findings": [item.__dict__ for item in findings],
                    },
                    indent=2,
                    default=str,
                )
            )
        else:
            from .console import print_perf_summary

            print_perf_summary(usage, findings)
        return 0
    if args.command == "optimize":
        changes = apply_profile(args.profile, apply=args.apply)
        from .console import print_changes

        print_changes(changes, applied=args.apply)
        if not args.apply:
            print("\nDry run only. Add --apply to write changes with backups.")
        return 0
    if args.command == "bench":
        before, after = benchmark(args.delay)
        if args.json:
            import json

            print(json.dumps({"before": before, "after": after}, default=lambda obj: obj.__dict__, indent=2))
        else:
            from .console import print_benchmark

            print_benchmark(before, after)
        return 0
    if args.command == "watch":
        from .console import print_snapshot

        count = 0
        try:
            while True:
                print("\033c", end="")
                print_snapshot("Browser Watch", take_snapshot())
                print("\nCtrl+C to stop.")
                count += 1
                if args.ticks and count >= args.ticks:
                    break
                import time

                time.sleep(max(args.interval, 1))
        except KeyboardInterrupt:
            print("\nStopped.")
        return 0
    if args.command == "restore":
        backups = list_backups()
        if args.index is None or args.list:
            from .console import print_backup_list

            print_backup_list(backups)
            if args.index is None:
                return 0
        if args.index < 1 or args.index > len(backups):
            print("Invalid backup index.", file=sys.stderr)
            return 2
        selected = backups[args.index - 1]
        if not args.apply:
            print(f"Dry run: would restore {selected.backup} -> {selected.original}")
            print("Add --apply to restore.")
            return 0
        restore_point = restore_backup(selected)
        print(f"Restored: {selected.original}")
        print(f"Previous current file backup: {restore_point}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
