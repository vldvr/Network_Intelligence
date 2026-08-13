"""Packet capture panel."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netintel.adapters.factory import build_packet_source
from netintel.cancellation import CancellationToken
from netintel.core.capture import CaptureSession, compile_bpf
from netintel.errors import BackendUnavailableError, NetIntelError
from netintel.models import CaptureFilter, CaptureStats, PacketRecord, Protocol
from netintel.ui.models import PacketTableModel
from netintel.ui.panels.base import OperationPanel
from netintel.ui.workers import Worker

FLUSH_INTERVAL_MS = 200


def _run_capture(
    session: CaptureSession,
    *,
    token: CancellationToken,
    on_progress: Callable[[Any], None],
) -> CaptureStats:
    for packet in session.stream(token=token):
        on_progress(packet)
    return session.stats


class CapturePanel(OperationPanel):
    title = "Packet Capture"
    description = (
        "Captures frame headers on an interface. Requires raw-socket "
        "privileges. Payloads are never decoded or stored — only addresses, "
        "ports and sizes. Capture only on networks you are responsible for."
    )
    start_label = "Capture"

    def __init__(self, parent: QWidget | None = None) -> None:
        self._model = PacketTableModel()
        self._pending: list[PacketRecord] = []
        super().__init__(parent)

        # Packets arrive faster than a table can usefully repaint, so they are
        # buffered and flushed on a timer. The capture thread is never blocked
        # by the speed of the UI.
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(FLUSH_INTERVAL_MS)
        self._flush_timer.timeout.connect(self._flush)

    def build_controls(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()

        self.interface_input = QComboBox()
        self.interface_input.setEditable(True)
        self._populate_interfaces()
        form.addRow("Interface", self.interface_input)

        filters = QHBoxLayout()
        self.protocol_input = QComboBox()
        self.protocol_input.addItem("any", None)
        for protocol in (Protocol.TCP, Protocol.UDP, Protocol.ICMP):
            self.protocol_input.addItem(protocol.value, protocol)
        filters.addWidget(QLabel("Protocol"))
        filters.addWidget(self.protocol_input)

        self.src_ip_input = _field("source IP")
        self.dst_ip_input = _field("destination IP")
        self.src_port_input = _field("source port")
        self.dst_port_input = _field("destination port")
        for widget in (
            self.src_ip_input,
            self.dst_ip_input,
            self.src_port_input,
            self.dst_port_input,
        ):
            widget.textChanged.connect(self._preview_filter)
            filters.addWidget(widget)

        self.limit_input = QSpinBox()
        self.limit_input.setRange(0, 1_000_000)
        self.limit_input.setSpecialValueText("no limit")
        self.limit_input.setPrefix("stop after ")
        filters.addWidget(self.limit_input)
        filters.addStretch(1)

        form.addRow("Filter", _wrap(filters))
        layout.addLayout(form)

        self.protocol_input.currentIndexChanged.connect(self._preview_filter)

        self.filter_label = QLabel("no filter — every frame will be captured")
        self.filter_label.setObjectName("previewLabel")
        layout.addWidget(self.filter_label)

    def build_output(self) -> QWidget:
        self.table = QTableView()
        self.table.setModel(self._model)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        return self.table

    def _populate_interfaces(self) -> None:
        try:
            for name in build_packet_source().interfaces():
                self.interface_input.addItem(name)
        except BackendUnavailableError as exc:
            # A missing capture backend must not stop the window from opening;
            # the other three tools are unaffected by it.
            self.interface_input.addItem("(capture backend unavailable)")
            self.interface_input.setEnabled(False)
            self.filter_label.setText(str(exc)) if hasattr(self, "filter_label") else None

    def _criteria(self) -> CaptureFilter:
        return CaptureFilter(
            protocol=self.protocol_input.currentData(),
            src_ip=self.src_ip_input.text().strip() or None,
            dst_ip=self.dst_ip_input.text().strip() or None,
            src_port=_optional_int(self.src_port_input.text()),
            dst_port=_optional_int(self.dst_port_input.text()),
        )

    def _preview_filter(self) -> None:
        """Show the compiled BPF expression as the filter is edited.

        Making the generated expression visible is both a debugging aid and an
        honesty measure: the user can see exactly what the kernel was asked to
        match rather than trusting a black box of checkboxes.
        """
        try:
            expression = compile_bpf(self._criteria())
        except NetIntelError as exc:
            self.filter_label.setText(f"invalid filter: {exc}")
            return
        self.filter_label.setText(
            f"BPF: {expression}" if expression else "no filter — every frame will be captured"
        )

    def create_worker(self) -> Worker:
        interface = self.interface_input.currentText().strip()
        if not interface or interface.startswith("("):
            raise NetIntelError("select a capture interface")

        limit = self.limit_input.value() or None
        session = CaptureSession(
            source=build_packet_source(),
            interface=interface,
            criteria=self._criteria(),
            max_packets=limit,
        )
        return Worker(_run_capture, session)

    def on_starting(self) -> None:
        self._model.clear()
        self._pending.clear()
        self._flush_timer.start()

    def on_progress(self, item: Any) -> None:
        if isinstance(item, PacketRecord):
            self._pending.append(item)

    def _flush(self) -> None:
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        at_bottom = _scrolled_to_bottom(self.table)
        self._model.extend(batch)
        if at_bottom:
            # Follow the tail only while the user is already at the bottom;
            # auto-scrolling out from under someone reading is hostile.
            self.table.scrollToBottom()

    def on_finished(self, result: Any) -> None:
        self._flush_timer.stop()
        self._flush()
        if result is None:
            self.set_status("cancelled")
            return
        self.set_status(f"{result.captured} packet(s), {result.bytes_seen / 1024:.1f} KiB")

    def on_failed(self, message: str) -> None:
        self._flush_timer.stop()
        super().on_failed(message)

    def append(self, text: str) -> None:
        # This panel renders into a table; stray text goes to the status line.
        self.set_status(text, error=True)


def _scrolled_to_bottom(table: QTableView) -> bool:
    bar = table.verticalScrollBar()
    return bool(bar.value() >= bar.maximum() - 2)


def _optional_int(text: str) -> int | None:
    candidate = text.strip()
    if not candidate:
        return None
    try:
        return int(candidate)
    except ValueError:
        # compile_bpf validates properly and produces the user-facing message.
        return -1


def _field(placeholder: str) -> QLineEdit:
    widget = QLineEdit()
    widget.setPlaceholderText(placeholder)
    widget.setClearButtonEnabled(True)
    return widget


def _wrap(inner: QHBoxLayout) -> QWidget:
    container = QWidget()
    container.setLayout(inner)
    return container
