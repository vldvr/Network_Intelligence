"""Host discovery panel."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from netintel.adapters.factory import build_discovery_backend, build_geoip_provider
from netintel.cancellation import CancellationToken
from netintel.core.discovery import (
    DiscoveryConfig,
    DiscoveryReport,
    DiscoveryService,
    GeoFilter,
)
from netintel.core.scope import ScopePolicy
from netintel.core.targets import parse_targets
from netintel.errors import TargetError
from netintel.models import HostRecord
from netintel.ui.panels.base import OperationPanel
from netintel.ui.workers import Worker


def _run_discovery(
    service: DiscoveryService,
    expression: str,
    config: DiscoveryConfig,
    *,
    token: CancellationToken,
    on_progress: Callable[[Any], None],
) -> DiscoveryReport:
    return service.discover(expression, config=config, token=token, on_host=on_progress)


class DiscoveryPanel(OperationPanel):
    title = "Host Discovery"
    description = (
        "Finds hosts that respond in an address range. Scanning is limited to "
        "private address space unless you declare an authorised scope — "
        "scanning networks you do not have permission to test is unlawful in "
        "many jurisdictions."
    )
    start_label = "Scan"

    def __init__(self, parent: QWidget | None = None) -> None:
        self._policy = ScopePolicy.load()
        super().__init__(parent)

    def build_controls(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()

        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("192.168.1.0/24, 10.0.0.5-40")
        self.targets_input.returnPressed.connect(self.start)
        self.targets_input.textChanged.connect(self._preview_targets)
        form.addRow("Range", self.targets_input)

        options = QHBoxLayout()
        self.backend_input = QComboBox()
        self.backend_input.addItems(["auto", "nmap", "tcp"])
        self.backend_input.setToolTip(
            "auto uses nmap when installed and falls back to a built-in TCP "
            "connect sweep, which needs no root and no external tools."
        )
        options.addWidget(QLabel("Backend"))
        options.addWidget(self.backend_input)

        self.timeout_input = QDoubleSpinBox()
        self.timeout_input.setRange(0.1, 30.0)
        self.timeout_input.setSingleStep(0.5)
        self.timeout_input.setValue(1.0)
        self.timeout_input.setSuffix(" s")
        options.addWidget(QLabel("Timeout/host"))
        options.addWidget(self.timeout_input)

        self.geo_checkbox = QCheckBox("Locate hosts")
        self.geo_checkbox.toggled.connect(self._toggle_geo_inputs)
        options.addWidget(self.geo_checkbox)
        options.addStretch(1)
        form.addRow("Options", _wrap(options))

        geo = QHBoxLayout()
        self.lat_input = QLineEdit()
        self.lat_input.setPlaceholderText("latitude, e.g. 51.5074")
        self.lon_input = QLineEdit()
        self.lon_input.setPlaceholderText("longitude, e.g. -0.1278")
        self.radius_input = QLineEdit()
        self.radius_input.setPlaceholderText("radius in km")
        geo.addWidget(self.lat_input)
        geo.addWidget(self.lon_input)
        geo.addWidget(self.radius_input)
        self._geo_row = _wrap(geo)
        form.addRow("Near", self._geo_row)

        layout.addLayout(form)

        self.scope_label = QLabel(self._policy.describe())
        self.scope_label.setWordWrap(True)
        self.scope_label.setObjectName("scopeLabel")
        layout.addWidget(self.scope_label)

        self.preview_label = QLabel("")
        self.preview_label.setObjectName("previewLabel")
        layout.addWidget(self.preview_label)

        self._toggle_geo_inputs(False)

    def _toggle_geo_inputs(self, enabled: bool) -> None:
        self._geo_row.setEnabled(enabled)

    def _preview_targets(self, text: str) -> None:
        """Validate as the user types.

        Parsing is pure and microsecond-scale, so it is safe on the UI thread —
        and finding out that a range is malformed before starting a scan beats
        finding out from a traceback after it.
        """
        expression = text.strip()
        if not expression:
            self.preview_label.setText("")
            return
        try:
            spec = parse_targets(expression, max_hosts=self._policy.max_hosts)
        except TargetError as exc:
            self.preview_label.setText(str(exc))
            return

        out_of_scope = sum(1 for address in spec if not self._policy.permits(address))
        message = f"{len(spec)} address(es)"
        if out_of_scope:
            message += f" — {out_of_scope} outside the authorised scope"
        self.preview_label.setText(message)

    def create_worker(self) -> Worker:
        geo_filter = None
        if self.geo_checkbox.isChecked() and self.lat_input.text().strip():
            geo_filter = GeoFilter(
                _as_float(self.lat_input.text(), "latitude"),
                _as_float(self.lon_input.text(), "longitude"),
                _as_float(self.radius_input.text(), "radius"),
            ).validated()

        config = DiscoveryConfig(
            timeout_s=self.timeout_input.value(),
            max_hosts=self._policy.max_hosts,
            geolocate=self.geo_checkbox.isChecked(),
            geo_filter=geo_filter,
        ).validated()

        service = DiscoveryService(
            build_discovery_backend(prefer=self.backend_input.currentText()),
            policy=self._policy,
            geoip=build_geoip_provider(),
        )
        return Worker(_run_discovery, service, self.targets_input.text().strip(), config)

    def on_progress(self, item: Any) -> None:
        if isinstance(item, HostRecord):
            ports = (
                "  ports " + ",".join(str(p) for p in item.open_ports) if item.open_ports else ""
            )
            self.append(f"up: {item.ip}{ports}")

    def on_finished(self, result: Any) -> None:
        if result is None:
            self.set_status("cancelled")
            return

        self.append("")
        for host in result.hosts:
            parts = [host.ip]
            if host.hostname:
                parts.append(host.hostname)
            if host.location is not None:
                parts.append(host.location.describe())
            if host.distance_km is not None:
                parts.append(f"{host.distance_km:.0f} km")
            self.append("  ".join(parts))

        summary = f"{len(result.hosts)} of {result.requested} responded"
        if result.filtered_out:
            summary += f", {result.filtered_out} outside the radius"
        if result.cancelled:
            summary += " (partial — cancelled)"
        self.set_status(summary)


def _as_float(text: str, label: str) -> float:
    try:
        return float(text.strip())
    except ValueError as exc:
        raise TargetError(f"{label} must be a number") from exc


def _wrap(inner: QHBoxLayout) -> QWidget:
    container = QWidget()
    container.setLayout(inner)
    return container
