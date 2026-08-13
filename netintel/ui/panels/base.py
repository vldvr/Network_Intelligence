"""Shared panel chrome.

Each of the four tools has the same shape: some inputs, a start/stop pair, a
status line, an output area. The original repeated that wiring — including
the button-state bookkeeping — four times, and the four copies had already
drifted apart. Here it exists once and the panels supply only what differs.
"""

from __future__ import annotations

from typing import Any

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from netintel.errors import NetIntelError
from netintel.ui.workers import Worker, WorkerHost

MAX_OUTPUT_LINES = 5000
"""Cap on retained output lines.

``QTextEdit.append`` keeps every line forever. A capture left running
overnight in the original would grow the document until the process was
killed; a block-count limit turns that into a scrollback window."""


class OperationPanel(QWidget):
    """Base class for a panel that runs one cancellable operation."""

    title = "Operation"
    description = ""
    start_label = "Start"
    stop_label = "Stop"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = WorkerHost()
        self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        layout = QVBoxLayout(self)

        if self.description:
            blurb = QLabel(self.description)
            blurb.setWordWrap(True)
            blurb.setObjectName("panelDescription")
            layout.addWidget(blurb)

        self.build_controls(layout)

        buttons = QHBoxLayout()
        self.start_button = QPushButton(self.start_label)
        self.stop_button = QPushButton(self.stop_label)
        self.stop_button.setEnabled(False)
        self.start_button.setDefault(True)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch(1)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")
        buttons.addWidget(self.status_label)
        layout.addLayout(buttons)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(MAX_OUTPUT_LINES)
        self.output.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.output.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        layout.addWidget(self.build_output() or self.output)

        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)

    def build_controls(self, layout: QVBoxLayout) -> None:
        """Add the panel's input widgets. Subclasses override."""

    def build_output(self) -> QWidget | None:
        """Return a custom output widget, or ``None`` to use the text view."""
        return None

    # ------------------------------------------------------------- operations

    def create_worker(self) -> Worker:
        """Build the worker for one run. Subclasses override."""
        raise NotImplementedError

    def start(self) -> None:
        if self._host.busy:
            self.set_status("already running")
            return

        try:
            worker = self.create_worker()
        except NetIntelError as exc:
            # Input validation failures are shown in place. A modal dialog per
            # typo — the original behaviour — trains people to dismiss dialogs
            # without reading them.
            self.set_status(str(exc), error=True)
            return

        worker.signals.progress.connect(self.on_progress)
        worker.signals.finished.connect(self.on_finished)
        worker.signals.failed.connect(self.on_failed)
        worker.signals.done.connect(self._on_done)

        self.on_starting()
        if not self._host.start(worker):
            self.set_status("already running")
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.set_status("running…")

    def stop(self) -> None:
        self._host.cancel()
        self.stop_button.setEnabled(False)
        self.set_status("stopping…")

    def shutdown(self) -> None:
        """Cancel and wait — called when the window is closing."""
        self._host.cancel()
        self._host.wait_for_done()

    # ---------------------------------------------------------------- signals

    def on_starting(self) -> None:
        self.output.clear()

    def on_progress(self, item: Any) -> None:
        self.append(str(item))

    def on_finished(self, result: Any) -> None:
        self.set_status("done")

    def on_failed(self, message: str) -> None:
        self.append(f"error: {message}")
        self.set_status(message, error=True)

    def _on_done(self) -> None:
        # Button state is restored here and nowhere else, so no error path can
        # leave the panel wedged with Start greyed out.
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    # ----------------------------------------------------------------- output

    def append(self, text: str) -> None:
        self.output.appendPlainText(text)

    def set_status(self, message: str, *, error: bool = False) -> None:
        self.status_label.setText(message)
        self.status_label.setProperty("state", "error" if error else "normal")
        # Re-polish so the stylesheet picks up the changed property.
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
