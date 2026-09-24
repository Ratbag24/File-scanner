"""Entry point.

With no arguments (for example when you double-click the .exe) the window opens.
With arguments it runs on the command line: ``filescanner scan <path>``.
"""

import sys


def main() -> int:
    if len(sys.argv) > 1:
        from .cli import main as cli_main

        return cli_main()
    from .gui import main as gui_main

    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
