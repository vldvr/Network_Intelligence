"""Packet capture and BPF filter compilation.

The original sniffer captured everything and then compared strings in a Python
callback, on the capture thread, once per frame — while also appending to a Qt
widget from that same thread. On an idle laptop link that survives; on
anything busy it drops frames and the UI stops repainting.

Filtering now happens in the kernel. :func:`compile_bpf` turns the user's
criteria into a BPF expression that libpcap applies before a frame is ever
copied to userspace.

Because that expression *is* an interpreted language, every value going into
it is validated first — an IP is parsed as an IP, a port as an integer in
range, a MAC against a strict pattern. Nothing reaches the compiler as an
unchecked string.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from netintel.cancellation import NEVER_CANCELLED, CancellationToken
from netintel.core.targets import parse_address
from netintel.errors import TargetError
from netintel.models import CaptureFilter, CaptureStats, PacketRecord, Protocol
from netintel.ports import PacketSource

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

PacketCallback = Callable[[PacketRecord], None]


def _validate_port(value: int | str, label: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise TargetError(f"{label} must be a number") from exc
    if not 1 <= port <= 65535:
        raise TargetError(f"{label} must be between 1 and 65535")
    return port


def _validate_mac(value: str, label: str) -> str:
    candidate = value.strip()
    if not _MAC_RE.match(candidate):
        raise TargetError(f"{label} must look like aa:bb:cc:dd:ee:ff")
    return candidate.lower()


def compile_bpf(criteria: CaptureFilter) -> str | None:
    """Compile capture criteria into a BPF expression.

    Returns ``None`` when no criteria were given, meaning "capture everything"
    — passing an empty string to libpcap is an error, not a wildcard.
    """
    terms: list[str] = []

    if criteria.protocol is not None and criteria.protocol is not Protocol.OTHER:
        terms.append(criteria.protocol.value)

    if criteria.src_ip:
        terms.append(f"src host {parse_address(criteria.src_ip)}")
    if criteria.dst_ip:
        terms.append(f"dst host {parse_address(criteria.dst_ip)}")

    if criteria.src_port is not None:
        terms.append(f"src port {_validate_port(criteria.src_port, 'source port')}")
    if criteria.dst_port is not None:
        terms.append(f"dst port {_validate_port(criteria.dst_port, 'destination port')}")

    if criteria.src_mac:
        terms.append(f"ether src {_validate_mac(criteria.src_mac, 'source MAC')}")
    if criteria.dst_mac:
        terms.append(f"ether dst {_validate_mac(criteria.dst_mac, 'destination MAC')}")

    if not terms:
        return None
    return " and ".join(terms)


@dataclass(slots=True)
class CaptureSession:
    """A bounded, observable capture run.

    Packets are held in a ring buffer. An unbounded list behind a live capture
    is a memory leak with a timer on it: leave the original sniffer running
    over lunch and it ends as an out-of-memory kill.
    """

    source: PacketSource
    interface: str
    criteria: CaptureFilter = field(default_factory=CaptureFilter)
    buffer_size: int = 10_000
    max_packets: int | None = None
    _packets: deque[PacketRecord] = field(default_factory=deque, init=False)
    _captured: int = field(default=0, init=False)
    _bytes: int = field(default=0, init=False)
    _started_at: datetime = field(default_factory=lambda: datetime.now(UTC), init=False)

    def __post_init__(self) -> None:
        if self.buffer_size < 1:
            raise TargetError("buffer size must be at least 1")
        self._packets = deque(maxlen=self.buffer_size)

    @property
    def packets(self) -> tuple[PacketRecord, ...]:
        """A snapshot of the retained packets, oldest first."""
        return tuple(self._packets)

    @property
    def stats(self) -> CaptureStats:
        return CaptureStats(
            captured=self._captured,
            bytes_seen=self._bytes,
            started_at=self._started_at,
        )

    def run(
        self,
        *,
        token: CancellationToken = NEVER_CANCELLED,
        on_packet: PacketCallback | None = None,
    ) -> CaptureStats:
        """Capture until cancelled, or until ``max_packets`` is reached."""
        for packet in self.stream(token=token):
            if on_packet is not None:
                on_packet(packet)
        return self.stats

    def stream(self, *, token: CancellationToken = NEVER_CANCELLED) -> Iterator[PacketRecord]:
        """Yield packets as they arrive.

        A generator rather than a callback-only API: it composes with ``take``,
        ``filter`` and ``for``, and it lets the caller decide the back-pressure
        policy instead of the capture loop imposing one.
        """
        bpf = compile_bpf(self.criteria)
        self._started_at = datetime.now(UTC)

        for packet in self.source.capture(
            self.interface, bpf_filter=bpf, should_continue=token.should_continue
        ):
            self._captured += 1
            self._bytes += packet.length
            self._packets.append(packet)
            yield packet

            if self.max_packets is not None and self._captured >= self.max_packets:
                break
            if token.cancelled:
                break


def format_packet(packet: PacketRecord) -> str:
    """One capture line, timestamped to the millisecond."""
    stamp = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
    return f"{stamp}  {packet.summary}"
