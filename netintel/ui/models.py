"""Qt item models.

A table model rather than a text widget for captured packets. Three reasons,
all of which the original ran into: a model keeps rendering proportional to
what is on screen rather than to what has been captured; rows can be sorted
and copied as data; and a ring buffer bounds memory without truncating a
document the user is reading.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from typing import Any

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt, QVariant

from netintel.models import PacketRecord

COLUMNS: tuple[str, ...] = (
    "Time",
    "Protocol",
    "Source",
    "Destination",
    "Length",
    "Flags",
)


class PacketTableModel(QAbstractTableModel):
    """Fixed-capacity table of captured packets, newest last."""

    def __init__(self, capacity: int = 20_000, parent: Any = None) -> None:
        super().__init__(parent)
        self._rows: deque[PacketRecord] = deque(maxlen=capacity)
        self._capacity = capacity

    # ------------------------------------------------------- Qt model protocol

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole
    ) -> Any:
        if role != Qt.DisplayRole or orientation != Qt.Horizontal:
            return QVariant()
        return COLUMNS[section]

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()
        packet = self._rows[index.row()]

        if role == Qt.DisplayRole:
            return _cell(packet, index.column())
        if role == Qt.TextAlignmentRole and index.column() == 4:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            return packet.summary
        return QVariant()

    # ------------------------------------------------------------- mutation

    def extend(self, packets: Sequence[PacketRecord]) -> None:
        """Append a batch of packets in one model reset-free update.

        Batching matters: emitting ``rowsInserted`` per packet on a busy link
        means one full layout pass per frame, and the UI thread stops keeping
        up long before the capture does.
        """
        if not packets:
            return

        overflow = max(0, len(self._rows) + len(packets) - self._capacity)
        if overflow:
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            for _ in range(overflow):
                self._rows.popleft()
            self.endRemoveRows()

        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(packets) - 1)
        self._rows.extend(packets)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def packets(self) -> tuple[PacketRecord, ...]:
        return tuple(self._rows)


def _cell(packet: PacketRecord, column: int) -> str:
    if column == 0:
        return packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
    if column == 1:
        return packet.protocol.value.upper()
    if column == 2:
        return _endpoint(packet.src_ip, packet.src_port, packet.src_mac)
    if column == 3:
        return _endpoint(packet.dst_ip, packet.dst_port, packet.dst_mac)
    if column == 4:
        return str(packet.length)
    if column == 5:
        return packet.tcp_flags or ""
    return ""


def _endpoint(ip: str | None, port: int | None, mac: str | None) -> str:
    host = ip or mac or "?"
    return f"{host}:{port}" if port is not None else host
