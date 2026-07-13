from __future__ import annotations

import json
from html import escape
from pathlib import Path

from .extensions import ExtensionFinding
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
            "tier": item.tier,
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
            f"{human_size(item.size_bytes)} | {item.files} | {safe} ({item.tier}) |"
        )
    lines.extend(
        [
            "",
            "Protected by design: history, cookies, saved passwords, autofill, bookmarks,",
            "session restore data and browser login databases are not cleanup targets.",
        ]
    )
    return "\n".join(lines) + "\n"


def extensions_to_json(extensions: list[ExtensionFinding]) -> str:
    payload = [
        {
            "browser": item.browser,
            "profile": item.profile,
            "extension_id": item.extension_id,
            "name": item.name,
            "version": item.version,
            "risk": item.risk,
            "permissions": list(item.permissions),
            "sensitive_permissions": list(item.sensitive_permissions),
            "path": str(item.path),
        }
        for item in extensions
    ]
    return json.dumps(payload, indent=2)


def to_html(candidates: list[Candidate], extensions: list[ExtensionFinding] | None = None) -> str:
    extensions = extensions or []
    total = sum(item.size_bytes for item in candidates if item.safe)
    rows = "\n".join(
        "<tr>"
        f"<td>{escape(item.browser)}</td>"
        f"<td>{escape(item.profile)}</td>"
        f"<td>{escape(item.label)}</td>"
        f"<td class='num'>{human_size(item.size_bytes)}</td>"
        f"<td class='num'>{item.files}</td>"
        f"<td>{escape(item.tier)}</td>"
        "</tr>"
        for item in sorted(candidates, key=lambda c: c.size_bytes, reverse=True)
    )
    ext_rows = "\n".join(
        "<tr>"
        f"<td>{escape(item.browser)}</td>"
        f"<td>{escape(item.profile)}</td>"
        f"<td>{escape(item.name)}</td>"
        f"<td>{escape(item.version)}</td>"
        f"<td><span class='risk {item.risk}'>{escape(item.risk)}</span></td>"
        f"<td>{escape(', '.join(item.sensitive_permissions) or 'none')}</td>"
        "</tr>"
        for item in sorted(extensions, key=lambda e: (e.risk, e.browser, e.name))
    )
    if not ext_rows:
        ext_rows = "<tr><td colspan='6'>No extensions found.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Browser Janitor Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #1f2937; }}
h1, h2 {{ margin-bottom: 8px; }}
.summary {{ padding: 16px; background: #eef6ff; border: 1px solid #b6d7ff; border-radius: 8px; }}
table {{ border-collapse: collapse; width: 100%; margin: 18px 0 28px; }}
th, td {{ border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }}
th {{ background: #f8fafc; }}
.num {{ text-align: right; white-space: nowrap; }}
.risk {{ padding: 2px 8px; border-radius: 999px; font-size: 12px; text-transform: uppercase; }}
.risk.high {{ background: #fee2e2; color: #991b1b; }}
.risk.medium {{ background: #fef3c7; color: #92400e; }}
.risk.low {{ background: #dcfce7; color: #166534; }}
.risk.info {{ background: #e0f2fe; color: #075985; }}
.note {{ color: #475569; }}
</style>
</head>
<body>
<h1>Browser Janitor Report</h1>
<div class="summary">
<strong>Safe reclaimable space:</strong> {human_size(total)}<br>
<span class="note">History, cookies, passwords, bookmarks, autofill and sessions are protected.</span>
</div>
<h2>Cleanup Candidates</h2>
<table>
<thead><tr><th>Browser</th><th>Profile</th><th>Target</th><th>Size</th><th>Files</th><th>Tier</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<h2>Extension Audit</h2>
<table>
<thead><tr><th>Browser</th><th>Profile</th><th>Extension</th><th>Version</th><th>Risk</th><th>Sensitive permissions</th></tr></thead>
<tbody>{ext_rows}</tbody>
</table>
</body>
</html>
"""


def write_report(
    path: Path,
    candidates: list[Candidate],
    fmt: str,
    extensions: list[ExtensionFinding] | None = None,
) -> None:
    if fmt == "json":
        path.write_text(to_json(candidates) + "\n", encoding="utf-8")
    elif fmt == "md":
        path.write_text(to_markdown(candidates), encoding="utf-8")
    elif fmt == "html":
        path.write_text(to_html(candidates, extensions), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
