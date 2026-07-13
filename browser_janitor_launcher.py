from __future__ import annotations

import sys
from pathlib import Path

from browser_janitor.cli import main


def pause() -> None:
    try:
        input("\nPress Enter to close...")
    except EOFError:
        pass


def run_interactive() -> int:
    while True:
        print("Browser Janitor")
        print("Safe browser cleanup: cache only, profile data protected.")
        print("-" * 64)
        print("1. Doctor summary + extension audit")
        print("2. Scan safe cleanup targets")
        print("3. Audit extensions")
        print("4. Clean dry-run")
        print("5. Clean safe targets now")
        print("6. Write HTML report")
        print("7. Performance/FPS audit")
        print("8. Apply gaming profile")
        print("9. Apply low-RAM profile")
        print("0. Exit")
        choice = input("\nChoose an option: ").strip()
        print()

        if choice == "1":
            code = main(["doctor"])
            pause()
            return code
        if choice == "2":
            code = main(["scan"])
            pause()
            return code
        if choice == "3":
            code = main(["extensions"])
            pause()
            return code
        if choice == "4":
            code = main(["clean"])
            pause()
            return code
        if choice == "5":
            confirm = input("This deletes only safe cache targets. Continue? [y/N]: ").strip().lower()
            if confirm == "y":
                code = main(["clean", "--apply"])
            else:
                print("Cancelled.")
                code = 0
            pause()
            return code
        if choice == "6":
            report = Path.cwd() / "browser-janitor-report.html"
            code = main(["doctor", "--report", str(report)])
            print(f"\nReport saved to: {report}")
            pause()
            return code
        if choice == "7":
            code = main(["perf"])
            pause()
            return code
        if choice == "8":
            confirm = input("Apply gaming profile with JSON backups? [y/N]: ").strip().lower()
            code = main(["optimize", "--profile", "gaming", "--apply"]) if confirm == "y" else 0
            if confirm != "y":
                print("Cancelled.")
            pause()
            return code
        if choice == "9":
            confirm = input("Apply low-RAM profile with JSON backups? [y/N]: ").strip().lower()
            code = main(["optimize", "--profile", "low-ram", "--apply"]) if confirm == "y" else 0
            if confirm != "y":
                print("Cancelled.")
            pause()
            return code
        if choice == "0":
            return 0

        print("Invalid option.\n")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise SystemExit(run_interactive())
    raise SystemExit(main())
