from __future__ import annotations

import json
from pathlib import Path

from .scanner import Candidate


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def to_json(candidates: list[Candidate]) -> str:
    payload = [
        {
            "browser": item.browser,
            "profile": item.profile,
            "label": item.label,
            "path": str(item.path),
            "size_bytes": item.size_bytes,
            "size": human_size(item.size_bytes),
            "files": item.files,
            "safe": item.safe,
            "reason": item.reason,
        }
        for item in candidates
    ]
    return json.dumps(payload, indent=2)


def to_markdown(candidates: list[Candidate]) -> str:
    total = sum(item.size_bytes for item in candidates if item.safe)
    lines = [
        "# Browser Janitor Report",
        "",
        f"Safe reclaimable space: **{human_size(total)}**",
        "",
        "| Browser | Profile | Target | Size | Files | Safe |",
        "|---|---|---|---:|---:|---|",
    ]
    for item in sorted(candidates, key=lambda c: c.size_bytes, reverse=True):
        safe = "yes" if item.safe else "blocked"
        lines.append(
            f"| {item.browser} | {item.profile} | {item.label} | "
            f"{human_size(item.size_bytes)} | {item.files} | {safe} |"
        )
    lines.extend(
        [
            "",
            "Protected by design: history, cookies, saved passwords, autofill, bookmarks,",
            "session restore data and browser login databases are not cleanup targets.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_report(path: Path, candidates: list[Candidate], fmt: str) -> None:
    if fmt == "json":
        path.write_text(to_json(candidates) + "\n", encoding="utf-8")
    elif fmt == "md":
        path.write_text(to_markdown(candidates), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
