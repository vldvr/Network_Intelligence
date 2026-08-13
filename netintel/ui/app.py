"""GUI entry point."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from netintel.errors import BackendUnavailableError


def run(argv: Sequence[str] | None = None) -> int:
    """Start the GUI. Returns the Qt exit code."""
    try:
        from PyQt5.QtCore import Qt
        from PyQt5.QtWidgets import QApplication
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise BackendUnavailableError(
            "PyQt5",
            "install the GUI extra with `pip install -e '.[gui]'`, or use the "
            "`netintel` command-line interface instead",
        ) from exc

    from netintel.ui.main_window import MainWindow, apply_style

    # Must be set before the QApplication exists, or it is ignored.
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)

    app = QApplication(list(argv if argv is not None else sys.argv))
    app.setApplicationName("NetworkIntelligence")
    apply_style(app)

    window = MainWindow()
    window.show()
    return int(app.exec_())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
