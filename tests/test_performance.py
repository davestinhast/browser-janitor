import json
import tempfile
import unittest
from pathlib import Path

from browser_janitor.performance import apply_profile, list_backups, restore_backup
from browser_janitor.rules import BrowserRoot


class PerformanceProfileTests(unittest.TestCase):
    def write_state(self, root: Path) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "Default").mkdir()
        path = root / "Local State"
        path.write_text(
            json.dumps(
                {
                    "profile": {"info_cache": {"Default": {"background_apps": True}}},
                    "edge": {"perf_center": {"efficiency_mode_v2_is_active": True}},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_apply_profile_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = self.write_state(root)
            before = state.read_text(encoding="utf-8")

            changes = apply_profile(
                "gaming",
                apply=False,
                roots=[BrowserRoot("Microsoft Edge", "chromium", root)],
            )

            self.assertTrue(changes)
            self.assertEqual(state.read_text(encoding="utf-8"), before)

    def test_apply_profile_writes_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = self.write_state(root)

            changes = apply_profile(
                "gaming",
                apply=True,
                roots=[BrowserRoot("Microsoft Edge", "chromium", root)],
            )
            data = json.loads(state.read_text(encoding="utf-8"))

            self.assertTrue(changes)
            self.assertFalse(data["profile"]["info_cache"]["Default"]["background_apps"])
            self.assertFalse(data["edge"]["perf_center"]["efficiency_mode_v2_is_active"])
            self.assertTrue(changes[0].backup.exists())

    def test_list_and_restore_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = self.write_state(root)
            original_text = state.read_text(encoding="utf-8")

            apply_profile(
                "gaming",
                apply=True,
                roots=[BrowserRoot("Microsoft Edge", "chromium", root)],
            )
            backups = list_backups([BrowserRoot("Microsoft Edge", "chromium", root)])

            self.assertEqual(len(backups), 1)
            restore_backup(backups[0])
            self.assertEqual(state.read_text(encoding="utf-8"), original_text)


if __name__ == "__main__":
    unittest.main()
