"""Main entry point script for running BoundaryX desktop application.

Launches the application loop and handles top-level execution.
"""

from __future__ import annotations

import sys

from boundaryx.bootstrap import bootstrap_application


def main(argv: list[str] | None = None) -> int:
    """Initialize and execute BoundaryX desktop application event loop.

    Args:
        argv: Optional list of command-line arguments.

    Returns:
        Process exit code integer.
    """
    app, window, db_manager, settings = bootstrap_application(argv)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
