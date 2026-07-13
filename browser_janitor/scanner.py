from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .rules import ALL_RULES, BrowserRoot, CleanRule, PROTECTED_NAMES


@dataclass(frozen=True)
class Candidate:
    browser: str
    family: str
    profile: str
    label: str
    path: Path
    size_bytes: int
    files: int
    safe: bool
    reason: str
    tier: str = "safe"


def default_roots() -> list[BrowserRoot]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))
    roots = [
        BrowserRoot("Google Chrome", "chromium", local / "Google" / "Chrome" / "User Data"),
        BrowserRoot("Microsoft Edge", "chromium", local / "Microsoft" / "Edge" / "User Data"),
        BrowserRoot("Brave", "chromium", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
        BrowserRoot("Chromium", "chromium", local / "Chromium" / "User Data"),
        BrowserRoot("Firefox", "firefox", roaming / "Mozilla" / "Firefox" / "Profiles"),
    ]
    return [root for root in roots if str(root.path) and root.path.exists()]


def find_profiles(root: BrowserRoot) -> list[Path]:
    if root.family == "firefox":
        return [p for p in root.path.iterdir() if p.is_dir()]

    profiles: list[Path] = []
    for child in root.path.iterdir():
        if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile ")):
            profiles.append(child)
    return profiles


def dir_stats(path: Path) -> tuple[int, int]:
    if path.is_file():
        return path.stat().st_size, 1

    total = 0
    files = 0
    for current, _, names in os.walk(path):
        for name in names:
            file_path = Path(current) / name
            try:
                total += file_path.stat().st_size
                files += 1
            except OSError:
                continue
    return total, files


def is_protected(path: Path) -> bool:
    return any(part.lower() in PROTECTED_NAMES for part in path.parts)


def scan(roots: list[BrowserRoot] | None = None) -> list[Candidate]:
    roots = roots or default_roots()
    candidates: list[Candidate] = []
    for root in roots:
        rules = [rule for rule in ALL_RULES if rule.family == root.family]
        for profile in find_profiles(root):
            for rule in rules:
                target = profile.joinpath(*rule.relative_parts)
                if not target.exists():
                    continue
                safe = rule.safe and not is_protected(target)
                size, files = dir_stats(target)
                candidates.append(
                    Candidate(
                        browser=root.name,
                        family=root.family,
                        profile=profile.name,
                        label=rule.label,
                        path=target,
                        size_bytes=size,
                        files=files,
                        safe=safe,
                        reason=rule.reason if safe else "Protected profile data guard blocked this path.",
                        tier=rule.tier,
                    )
                )
    return candidates


def remove_candidate(candidate: Candidate) -> None:
    if not candidate.safe:
        raise ValueError(f"Refusing to clean protected target: {candidate.path}")
    if is_protected(candidate.path):
        raise ValueError(f"Refusing to clean protected profile data: {candidate.path}")

    if candidate.path.is_dir():
        shutil.rmtree(candidate.path)
    elif candidate.path.exists():
        candidate.path.unlink()
