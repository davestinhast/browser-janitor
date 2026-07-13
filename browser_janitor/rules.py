from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BrowserRoot:
    name: str
    family: str
    path: Path


@dataclass(frozen=True)
class CleanRule:
    family: str
    relative_parts: tuple[str, ...]
    label: str
    safe: bool = True
    reason: str = "Regenerable browser cache."
    tier: str = "safe"


PROTECTED_NAMES = {
    "bookmarks",
    "bookmarks.bak",
    "cookies",
    "cookies-journal",
    "favicons",
    "favicons-journal",
    "form history",
    "history",
    "history-journal",
    "key4.db",
    "logins.json",
    "login data",
    "login data-journal",
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "preferences",
    "secure preferences",
    "session storage",
    "sessions",
    "sessionstore-backups",
    "shortcuts",
    "top sites",
    "web data",
}


CHROMIUM_RULES = (
    CleanRule("chromium", ("Cache",), "HTTP cache"),
    CleanRule("chromium", ("Code Cache",), "JavaScript/WASM code cache"),
    CleanRule("chromium", ("GPUCache",), "GPU cache"),
    CleanRule("chromium", ("DawnCache",), "WebGPU Dawn cache"),
    CleanRule("chromium", ("GrShaderCache",), "Graphics shader cache"),
    CleanRule("chromium", ("ShaderCache",), "Shader cache"),
    CleanRule("chromium", ("Crashpad", "reports"), "Crash reports"),
    CleanRule("chromium", ("BrowserMetrics",), "Browser metrics logs"),
    CleanRule(
        "chromium",
        ("Service Worker", "CacheStorage"),
        "Service worker cache",
        reason="Offline/site cache. May make the first reload slower but should not sign users out.",
        tier="standard",
    ),
)

FIREFOX_RULES = (
    CleanRule("firefox", ("cache2",), "HTTP cache"),
    CleanRule("firefox", ("startupCache",), "Startup cache"),
    CleanRule("firefox", ("jumpListCache",), "Jump list cache"),
    CleanRule("firefox", ("thumbnails",), "Page thumbnails"),
    CleanRule("firefox", ("crashes", "pending"), "Pending crash reports"),
)

ALL_RULES = CHROMIUM_RULES + FIREFOX_RULES
