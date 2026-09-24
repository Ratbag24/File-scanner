"""Launcher used when building the executable with PyInstaller."""

import sys

from filescanner.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
