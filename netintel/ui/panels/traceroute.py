"""Traceroute panel."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PyQt5.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
)

from netintel.adapters.factory import build_geoip_provider, build_probe_sender, build_resolver
from netintel.cancellation import CancellationToken
from netintel.core.traceroute import TraceConfig, Tracer, format_hop
from netintel.models import Hop, TraceResult
from netintel.ui.panels.base import OperationPanel
from netintel.ui.workers import Worker


def _run_trace(
    tracer: Tracer,
    destination: str,
    *,
    token: CancellationToken,
    on_progress: Callable[[Any], None],
) -> TraceResult:
    return tracer.trace(destination, token=token, on_hop=on_progress)


class TraceroutePanel(OperationPanel):
    title = "Traceroute"
    description = (
        "Measures the path and per-hop latency to a destination. "
        "Sending probes requires raw-socket privileges."
    )
    start_label = "Trace"

    def build_controls(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()

        self.destination_input = QLineEdit()
        self.destination_input.setPlaceholderText("hostname or IP, e.g. example.com")
        self.destination_input.returnPressed.connect(self.start)
        form.addRow("Destination", self.destination_input)

        options = QHBoxLayout()
        self.max_hops_input = QSpinBox()
        self.max_hops_input.setRange(1, 255)
        self.max_hops_input.setValue(30)
        options.addWidget(QLabel("Max hops"))
        options.addWidget(self.max_hops_input)

        self.probes_input = QSpinBox()
        self.probes_input.setRange(1, 10)
        self.probes_input.setValue(3)
        options.addWidget(QLabel("Probes/hop"))
        options.addWidget(self.probes_input)

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 30)
        self.timeout_input.setValue(2)
        self.timeout_input.setSuffix(" s")
        options.addWidget(QLabel("Timeout"))
        options.addWidget(self.timeout_input)

        self.resolve_checkbox = QCheckBox("Resolve names")
        self.resolve_checkbox.setChecked(True)
        options.addWidget(self.resolve_checkbox)

        self.geo_checkbox = QCheckBox("Locate hops")
        self.geo_checkbox.setToolTip(
            "Annotate each hop with an approximate location from a public "
            "GeoIP service. City-level at best."
        )
        options.addWidget(self.geo_checkbox)
        options.addStretch(1)

        form.addRow("Options", _wrap(options))
        layout.addLayout(form)

    def create_worker(self) -> Worker:
        config = TraceConfig(
            max_hops=self.max_hops_input.value(),
            probes_per_hop=self.probes_input.value(),
            timeout_s=float(self.timeout_input.value()),
            resolve_names=self.resolve_checkbox.isChecked(),
            geolocate=self.geo_checkbox.isChecked(),
        ).validated()

        tracer = Tracer(
            build_probe_sender(),
            build_resolver(enabled=config.resolve_names),
            geoip=build_geoip_provider() if config.geolocate else None,
            config=config,
        )
        return Worker(_run_trace, tracer, self.destination_input.text().strip())

    def on_progress(self, item: Any) -> None:
        if isinstance(item, Hop):
            self.append(format_hop(item))

    def on_finished(self, result: Any) -> None:
        if result is None:
            self.set_status("cancelled")
            return
        if result.reached:
            self.set_status(
                f"reached {result.destination_ip} in {len(result.hops)} hops "
                f"({result.duration_s:.1f}s)"
            )
        else:
            self.set_status("destination not reached")
            self.append(
                "The path stopped short of the destination. Routers that drop "
                "ICMP show as '*'; this does not by itself mean the host is down."
            )


def _wrap(inner: QHBoxLayout) -> Any:
    from PyQt5.QtWidgets import QWidget

    container = QWidget()
    container.setLayout(inner)
    return container
