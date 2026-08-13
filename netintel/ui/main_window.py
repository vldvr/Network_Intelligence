"""Main window."""

from __future__ import annotations

from typing import Any

from PyQt5.QtCore import QSettings, Qt
from PyQt5.QtGui import QCloseEvent
from PyQt5.QtWidgets import QLabel, QMainWindow, QMessageBox, QTabWidget

from netintel import __version__
from netintel.core.scope import ScopePolicy
from netintel.privileges import check_raw_socket_privileges
from netintel.ui.panels import (
    CapturePanel,
    DiscoveryPanel,
    GeolocationPanel,
    TraceroutePanel,
)
from netintel.ui.panels.base import OperationPanel

PANELS: tuple[type[OperationPanel], ...] = (
    TraceroutePanel,
    GeolocationPanel,
    DiscoveryPanel,
    CapturePanel,
)


class MainWindow(QMainWindow):
    """Hosts the tool panels and the application-wide status."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"NetworkIntelligence {__version__}")
        self._settings = QSettings("NetworkIntelligence", "app")

        self._tabs = QTabWidget()
        self._panels: list[OperationPanel] = []
        for panel_class in PANELS:
            panel = panel_class()
            self._panels.append(panel)
            self._tabs.addTab(panel, panel.title)
        self.setCentralWidget(self._tabs)

        self._build_menu()
        self._build_status_bar()
        self._restore_geometry()

    def _build_menu(self) -> None:
        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("Authorised scope…", self._show_scope)
        help_menu.addAction("About", self._show_about)

    def _build_status_bar(self) -> None:
        status = check_raw_socket_privileges()
        label = QLabel(
            f"raw sockets: {status.detail}"
            if status.available
            else f"raw sockets: {status.detail} — traceroute and capture will fail"
        )
        label.setObjectName("privilegeLabel")
        label.setProperty("state", "normal" if status.available else "warning")
        if not status.available:
            label.setToolTip(status.hint)
        self.statusBar().addPermanentWidget(label)
        self.statusBar().showMessage("Ready")

    def _show_scope(self) -> None:
        policy = ScopePolicy.load()
        QMessageBox.information(
            self,
            "Authorised scope",
            "Active scanning is restricted to:\n\n"
            + "\n".join(f"  {network}" for network in policy.allowed)
            + f"\n\nSource: {policy.note}\nHost limit per scan: {policy.max_hosts}"
            + "\n\nTo scan other networks, create a netintel-scope.json listing "
            "the prefixes you are authorised to test.",
        )

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "NetworkIntelligence",
            f"<b>NetworkIntelligence {__version__}</b>"
            "<p>Traceroute, geolocation, host discovery and packet capture.</p>"
            "<p>The same engine backs the <code>netintel</code> command-line "
            "interface; this window is a front end over it.</p>",
        )

    def _restore_geometry(self) -> None:
        geometry = self._settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        else:
            self.resize(1100, 720)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop in-flight work before the widgets it reports to are destroyed."""
        self._settings.setValue("window/geometry", self.saveGeometry())
        for panel in self._panels:
            panel.shutdown()
        super().closeEvent(event)


STYLESHEET = """
QWidget { font-size: 13px; }
QLabel#panelDescription { color: palette(mid); padding: 2px 0 6px 0; }
QLabel#previewLabel, QLabel#scopeLabel { color: palette(mid); font-size: 12px; }
QLabel#statusLabel { padding: 0 8px; }
QLabel#statusLabel[state="error"] { color: #c0392b; }
QLabel#privilegeLabel[state="warning"] { color: #b9770e; }
QPlainTextEdit, QTableView { font-family: "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace; }
QTableView { gridline-color: palette(midlight); }
"""


def apply_style(app: Any) -> None:
    """Apply the application stylesheet.

    Colours are taken from the palette wherever possible so the window follows
    the system light/dark setting instead of hard-coding one of them.
    """
    app.setStyleSheet(STYLESHEET)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
