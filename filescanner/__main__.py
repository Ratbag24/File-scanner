"""Entry point.

With no arguments (for example when you double-click the .exe) the window opens.
With arguments it runs on the command line: ``filescanner scan <path>``.
"""

import os
import sys


def ensure_streams() -> bool:
    """Give Python somewhere to write when there is no console.

    The windowed Windows app starts with ``sys.stdout`` and ``sys.stderr`` set to
    None, and some libraries (oletools' colour output) crash when they try to use
    them. Returns True when a console was missing.
    """
    missing = False
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            missing = True
    return missing


def main() -> int:
    no_console = ensure_streams()
    args = sys.argv[1:]
    # Files dropped onto the windowed app arrive as arguments; open them in the window.
    if args and not no_console:
        from .cli import main as cli_main

        return cli_main()
    from .gui import main as gui_main

    return gui_main([a for a in args if os.path.exists(a)])


if __name__ == "__main__":
    sys.exit(main())
