"""Build the standalone app with PyInstaller.

    python build.py

Creates, in the dist/ folder:
  FileScanner(.exe)       - the window app (double-click it)
  filescanner-cli(.exe)   - command-line version
"""

import os
import sys

import PyInstaller.__main__

SEP = os.pathsep
COMMON = [
    "run_scanner.py",
    "--onefile",
    "--noconfirm",
    "--clean",
    f"--add-data=filescanner/rules{SEP}filescanner/rules",
    "--collect-submodules=oletools",
    "--collect-data=oletools",
]
try:
    import tkinterdnd2  # noqa: F401
    COMMON.append("--collect-all=tkinterdnd2")
except ImportError:
    print("tkinterdnd2 not installed: the app will be built without drag-and-drop")

if __name__ == "__main__":
    PyInstaller.__main__.run(COMMON + ["--name=FileScanner", "--windowed"])
    PyInstaller.__main__.run(COMMON + ["--name=filescanner-cli", "--console"])
    print("\nDone. Your app is in the dist folder.")
    sys.exit(0)
