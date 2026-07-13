from __future__ import annotations

from collections import defaultdict

from .extensions import ExtensionFinding
from .performance import AppliedChange, PerfFinding, ProcessUsage
from .report import human_size
from .scanner import Candidate


def print_banner() -> None:
    print("Browser Janitor")
    print("Safe browser cleanup: cache only, profile data protected.")
    print("-" * 64)


def print_scan_summary(candidates: list[Candidate]) -> None:
    safe = [item for item in candidates if item.safe]
    total = sum(item.size_bytes for item in safe)
    by_browser: dict[str, int] = defaultdict(int)
    for item in safe:
        by_browser[item.browser] += item.size_bytes

    print_banner()
    print(f"Safe targets: {len(safe)}")
    print(f"Reclaimable:  {human_size(total)}")
    print()
    for browser, size in sorted(by_browser.items(), key=lambda item: item[1], reverse=True):
        print(f"{browser:<18} {human_size(size):>10}")
    print()
    print("Top cleanup targets:")
    for item in sorted(safe, key=lambda c: c.size_bytes, reverse=True)[:10]:
        print(f"  {human_size(item.size_bytes):>10}  {item.browser} / {item.profile} / {item.label}")
    print()
    print("Protected: history, cookies, passwords, bookmarks, autofill, sessions.")


def print_extension_summary(extensions: list[ExtensionFinding]) -> None:
    print_banner()
    print(f"Extensions found: {len(extensions)}")
    print()
    if not extensions:
        print("No extensions found.")
        return
    for item in sorted(extensions, key=lambda e: (e.risk, e.browser, e.name)):
        sensitive = ", ".join(item.sensitive_permissions) or "none"
        print(f"{item.risk.upper():<6} {item.browser:<16} {item.name} ({item.version})")
        print(f"       sensitive permissions: {sensitive}")


def print_perf_summary(usage: list[ProcessUsage], findings: list[PerfFinding]) -> None:
    print_banner()
    print("Live browser resource usage:")
    if not usage:
        print("  No running browser processes found, or process usage is unavailable.")
    for item in sorted(usage, key=lambda p: p.memory_bytes, reverse=True):
        print(f"  {item.browser:<16} {item.count:>3} processes  {human_size(item.memory_bytes):>10} RAM")
    print()
    print("Performance findings:")
    if not findings:
        print("  No major performance findings.")
    for item in findings:
        print(f"  {item.severity.upper():<6} {item.browser:<16} {item.title}")
        print(f"         {item.detail}")
    print()
    print("Profiles:")
    print("  gaming   = reduce background browser work for FPS-sensitive use")
    print("  low-ram  = favor memory reduction, especially inactive tabs")
    print("  balanced = safe baseline, background apps off")


def print_changes(changes: list[AppliedChange], applied: bool) -> None:
    if not changes:
        print("No changes needed.")
        return
    mode = "Applied" if applied else "Planned"
    print(f"{mode} changes:")
    for item in changes:
        print(f"  {item.browser}: {item.key}")
        print(f"       {item.old_value!r} -> {item.new_value!r}")
        if applied:
            print(f"       backup: {item.backup}")
