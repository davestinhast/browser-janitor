from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .extensions import scan_extensions
from .rules import BrowserRoot
from .scanner import default_roots, find_profiles


BROWSER_PROCESSES = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "brave.exe": "Brave",
    "firefox.exe": "Firefox",
}


@dataclass(frozen=True)
class ProcessUsage:
    browser: str
    process_name: str
    count: int
    memory_bytes: int


@dataclass(frozen=True)
class PerfFinding:
    browser: str
    profile: str
    severity: str
    title: str
    detail: str


@dataclass(frozen=True)
class AppliedChange:
    browser: str
    file: Path
    key: str
    old_value: object
    new_value: object
    backup: Path


@dataclass(frozen=True)
class BrowserSnapshot:
    timestamp: str
    usage: list[ProcessUsage]
    total_memory_bytes: int
    total_processes: int


@dataclass(frozen=True)
class BackupFile:
    browser: str
    original: Path
    backup: Path
    created: str


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def write_json_with_backup(path: Path, data: dict) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.browser-janitor-{stamp}.bak")
    shutil.copy2(path, backup)
    path.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return backup


def get_nested(data: dict, parts: tuple[str, ...], default: object = None) -> object:
    current: object = data
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_nested(data: dict, parts: tuple[str, ...], value: object) -> object:
    current = data
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    old = current.get(parts[-1])
    current[parts[-1]] = value
    return old


def local_state_path(root: BrowserRoot) -> Path:
    return root.path / "Local State"


def process_usage() -> list[ProcessUsage]:
    if os.name != "nt":
        return []
    try:
        raw = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process chrome,msedge,brave,firefox -ErrorAction SilentlyContinue | "
                "Group-Object ProcessName | ForEach-Object { "
                "[PSCustomObject]@{Name=$_.Name;Count=$_.Count;Memory=($_.Group | Measure-Object WorkingSet64 -Sum).Sum} "
                "} | ConvertTo-Json",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return []
    if not raw:
        return []
    payload = json.loads(raw)
    if isinstance(payload, dict):
        payload = [payload]
    usage: list[ProcessUsage] = []
    for item in payload:
        process_name = f"{str(item.get('Name', '')).lower()}.exe"
        usage.append(
            ProcessUsage(
                browser=BROWSER_PROCESSES.get(process_name, process_name),
                process_name=process_name,
                count=int(item.get("Count") or 0),
                memory_bytes=int(item.get("Memory") or 0),
            )
        )
    return usage


def take_snapshot() -> BrowserSnapshot:
    usage = process_usage()
    return BrowserSnapshot(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        usage=usage,
        total_memory_bytes=sum(item.memory_bytes for item in usage),
        total_processes=sum(item.count for item in usage),
    )


def benchmark(delay: int = 5) -> tuple[BrowserSnapshot, BrowserSnapshot]:
    before = take_snapshot()
    time.sleep(max(delay, 0))
    after = take_snapshot()
    return before, after


def audit_performance() -> tuple[list[ProcessUsage], list[PerfFinding]]:
    usage = process_usage()
    findings: list[PerfFinding] = []
    roots = default_roots()

    for root in roots:
        state = read_json(local_state_path(root))
        for profile in find_profiles(root):
            background = get_nested(state, ("profile", "info_cache", profile.name, "background_apps"))
            if background is True:
                findings.append(
                    PerfFinding(
                        root.name,
                        profile.name,
                        "high",
                        "Background apps are enabled",
                        "Browser apps can keep processes alive after the window closes, costing RAM and CPU.",
                    )
                )
        if root.name == "Microsoft Edge":
            perf = get_nested(state, ("edge", "perf_center"), {})
            if isinstance(perf, dict):
                if perf.get("efficiency_mode_v2_is_active") is True:
                    findings.append(
                        PerfFinding(
                            root.name,
                            "all",
                            "medium",
                            "Efficiency mode is active",
                            "Good for battery/RAM, but it can reduce foreground responsiveness and FPS-sensitive workloads.",
                        )
                    )
                if perf.get("perf_game_mode") is not True:
                    findings.append(
                        PerfFinding(
                            root.name,
                            "all",
                            "medium",
                            "Game mode is not enabled",
                            "Edge exposes a game/performance mode that can reduce browser interference while gaming.",
                        )
                    )

    for ext in scan_extensions():
        if ext.risk in {"high", "medium"}:
            findings.append(
                PerfFinding(
                    ext.browser,
                    ext.profile,
                    ext.risk,
                    f"Review extension: {ext.name}",
                    "Extensions with broad permissions can run background scripts and add CPU/RAM overhead.",
                )
            )

    for item in usage:
        if item.count >= 20:
            findings.append(
                PerfFinding(
                    item.browser,
                    "running",
                    "medium",
                    "Many browser processes are running",
                    f"{item.count} processes are using memory now. Close unused windows or use low-ram profile.",
                )
            )
    return usage, findings


def apply_profile(
    profile: str,
    apply: bool = False,
    roots: list[BrowserRoot] | None = None,
) -> list[AppliedChange]:
    if profile not in {"gaming", "low-ram", "balanced"}:
        raise ValueError("profile must be gaming, low-ram or balanced")

    changes: list[AppliedChange] = []
    for root in roots or default_roots():
        if root.family != "chromium":
            continue
        path = local_state_path(root)
        data = read_json(path)
        if not data:
            continue

        planned: list[tuple[tuple[str, ...], object]] = []
        for profile_path in find_profiles(root):
            planned.append((("profile", "info_cache", profile_path.name, "background_apps"), False))

        if root.name == "Microsoft Edge":
            if profile == "gaming":
                planned.extend(
                    [
                        (("edge", "perf_center", "perf_game_mode"), True),
                        (("edge", "perf_center", "efficiency_mode_v2_is_active"), False),
                        (("edge", "perf_center", "performance_mode_is_on"), True),
                        (("edge", "perf_center", "performance_mode"), 3),
                    ]
                )
            elif profile == "low-ram":
                planned.extend(
                    [
                        (("edge", "perf_center", "efficiency_mode_v2_is_active"), True),
                        (("edge", "perf_center", "performance_mode_is_on"), True),
                    ]
                )

        touched = False
        old_values: list[tuple[str, object, object]] = []
        for key, value in planned:
            old = get_nested(data, key)
            if old != value:
                touched = True
                old_values.append((".".join(key), old, value))
                set_nested(data, key, value)

        if touched:
            backup = path.with_suffix(".dry-run")
            if apply:
                backup = write_json_with_backup(path, data)
            for key, old, new in old_values:
                changes.append(AppliedChange(root.name, path, key, old, new, backup))

    return changes


def list_backups(roots: list[BrowserRoot] | None = None) -> list[BackupFile]:
    backups: list[BackupFile] = []
    for root in roots or default_roots():
        for backup in root.path.glob("*.browser-janitor-*.bak"):
            original_name = backup.name.split(".browser-janitor-", 1)[0]
            original = backup.with_name(original_name)
            try:
                created = datetime.fromtimestamp(backup.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            except OSError:
                created = "unknown"
            backups.append(BackupFile(root.name, original, backup, created))
    return sorted(backups, key=lambda item: item.backup.stat().st_mtime if item.backup.exists() else 0, reverse=True)


def restore_backup(backup: BackupFile) -> Path:
    restore_point = backup.original.with_name(
        f"{backup.original.name}.before-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
    )
    if backup.original.exists():
        shutil.copy2(backup.original, restore_point)
    shutil.copy2(backup.backup, backup.original)
    return restore_point
