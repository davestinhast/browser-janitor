import tempfile
import unittest
from pathlib import Path

from browser_janitor.rules import BrowserRoot
from browser_janitor.scanner import Candidate, is_protected, remove_candidate, scan


def write_file(path: Path, content: bytes = b"x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


class ScannerTests(unittest.TestCase):
    def test_chromium_scan_finds_safe_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "Default"
            write_file(profile / "Cache" / "Cache_Data" / "entry", b"abc")
            write_file(profile / "History", b"do-not-touch")

            results = scan([BrowserRoot("Test Chrome", "chromium", root)])

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].label, "HTTP cache")
            self.assertTrue(results[0].safe)
            self.assertEqual(results[0].size_bytes, 3)

    def test_protected_names_are_case_insensitive(self) -> None:
        self.assertTrue(is_protected(Path("Default") / "Login Data"))
        self.assertTrue(is_protected(Path("Default") / "cookies"))
        self.assertTrue(is_protected(Path("profile") / "sessionstore-backups"))

    def test_remove_refuses_protected_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "Default" / "History"
            write_file(target, b"abc")
            candidate = Candidate(
                browser="Test Chrome",
                family="chromium",
                profile="Default",
                label="Protected history",
                path=target,
                size_bytes=3,
                files=1,
                safe=False,
                reason="Protected profile data guard blocked this path.",
            )

            self.assertFalse(candidate.safe)
            with self.assertRaisesRegex(ValueError, "protected"):
                remove_candidate(candidate)

    def test_firefox_scan_uses_profiles_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "abc.default-release"
            write_file(profile / "cache2" / "entries" / "entry", b"abcd")

            results = scan([BrowserRoot("Firefox", "firefox", root)])

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].browser, "Firefox")
            self.assertEqual(results[0].profile, "abc.default-release")
            self.assertEqual(results[0].size_bytes, 4)


if __name__ == "__main__":
    unittest.main()
