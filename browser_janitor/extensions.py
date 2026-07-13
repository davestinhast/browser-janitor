from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .scanner import default_roots, find_profiles


SENSITIVE_PERMISSIONS = {
    "<all_urls>",
    "activeTab",
    "cookies",
    "debugger",
    "history",
    "management",
    "nativeMessaging",
    "proxy",
    "scripting",
    "tabs",
    "webRequest",
    "webRequestBlocking",
}


@dataclass(frozen=True)
class ExtensionFinding:
    browser: str
    profile: str
    extension_id: str
    name: str
    version: str
    permissions: tuple[str, ...]
    sensitive_permissions: tuple[str, ...]
    path: Path

    @property
    def risk(self) -> str:
        count = len(self.sensitive_permissions)
        if count >= 4:
            return "high"
        if count >= 2:
            return "medium"
        if count == 1:
            return "low"
        return "info"


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _manifest_name(manifest: dict) -> str:
    name = str(manifest.get("name") or "Unknown extension")
    if name.startswith("__MSG_"):
        return "Localized extension"
    return name


def scan_chromium_extensions() -> list[ExtensionFinding]:
    findings: list[ExtensionFinding] = []
    for root in default_roots():
        if root.family != "chromium":
            continue
        for profile in find_profiles(root):
            ext_root = profile / "Extensions"
            if not ext_root.exists():
                continue
            for ext_dir in ext_root.iterdir():
                if not ext_dir.is_dir():
                    continue
                versions = [p for p in ext_dir.iterdir() if p.is_dir()]
                if not versions:
                    continue
                latest = sorted(versions, key=lambda p: p.name)[-1]
                manifest = _read_json(latest / "manifest.json")
                if not manifest:
                    continue
                permissions = tuple(
                    sorted(
                        {
                            str(item)
                            for key in ("permissions", "host_permissions", "optional_permissions")
                            for item in manifest.get(key, [])
                        }
                    )
                )
                sensitive = tuple(p for p in permissions if p in SENSITIVE_PERMISSIONS or p.startswith("*://"))
                findings.append(
                    ExtensionFinding(
                        browser=root.name,
                        profile=profile.name,
                        extension_id=ext_dir.name,
                        name=_manifest_name(manifest),
                        version=str(manifest.get("version") or latest.name),
                        permissions=permissions,
                        sensitive_permissions=sensitive,
                        path=latest,
                    )
                )
    return findings


def scan_firefox_extensions() -> list[ExtensionFinding]:
    findings: list[ExtensionFinding] = []
    for root in default_roots():
        if root.family != "firefox":
            continue
        for profile in find_profiles(root):
            payload = _read_json(profile / "extensions.json")
            for addon in payload.get("addons", []):
                if addon.get("type") != "extension":
                    continue
                location = str(addon.get("location") or "")
                if addon.get("hidden") or location.startswith("app-builtin"):
                    continue
                permissions = tuple(sorted(str(p) for p in addon.get("userPermissions", {}).get("permissions", [])))
                sensitive = tuple(p for p in permissions if p in SENSITIVE_PERMISSIONS or p.startswith("*://"))
                findings.append(
                    ExtensionFinding(
                        browser=root.name,
                        profile=profile.name,
                        extension_id=str(addon.get("id") or "unknown"),
                        name=str(addon.get("defaultLocale", {}).get("name") or addon.get("id") or "Unknown extension"),
                        version=str(addon.get("version") or "unknown"),
                        permissions=permissions,
                        sensitive_permissions=sensitive,
                        path=profile / "extensions.json",
                    )
                )
    return findings


def scan_extensions() -> list[ExtensionFinding]:
    return scan_chromium_extensions() + scan_firefox_extensions()
