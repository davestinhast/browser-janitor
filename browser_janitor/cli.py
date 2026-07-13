from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .report import human_size, to_json, to_markdown, write_report
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
    scan_cmd.add_argument("--report", type=Path, help="Write a Markdown report to this path.")

    clean_cmd = sub.add_parser("clean", help="Clean safe cache targets.")
    clean_cmd.add_argument("--apply", action="store_true", help="Actually delete safe cache targets.")
    clean_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON summary.")
    clean_cmd.add_argument("--report", type=Path, help="Write a Markdown report before cleaning.")

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    candidates = scan()
    if args.report:
        write_report(args.report, candidates, "md")
    if args.json:
        print(to_json(candidates))
        return 0
    print(to_markdown(candidates))
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    candidates = scan()
    safe = [item for item in candidates if item.safe]
    total = sum(item.size_bytes for item in safe)

    if args.report:
        write_report(args.report, candidates, "md")

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
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
