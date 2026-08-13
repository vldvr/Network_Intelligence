"""Domain models.

These are the only types that cross a layer boundary. ``core`` produces them,
the CLI serialises them to JSON, the GUI renders them into tables. Keeping the
front ends on a shared vocabulary is what stops presentation logic from
drifting apart between the two.

All models are frozen: results are facts about an observation that already
happened, so nothing downstream has a reason to mutate them.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any

JsonDict = dict[str, Any]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Protocol(StrEnum):
    """Transport protocols this toolkit understands."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class HopKind(StrEnum):
    """What a traceroute probe came back as."""

    ROUTER = "router"
    """An intermediate router replied with ICMP time-exceeded."""

    DESTINATION = "destination"
    """The target itself replied — the trace is complete."""

    UNREACHABLE = "unreachable"
    """A router replied with ICMP destination-unreachable."""

    TIMEOUT = "timeout"
    """No reply within the probe timeout."""


@dataclass(frozen=True, slots=True)
class GeoLocation:
    """Approximate physical location of an IP address.

    ``accuracy_note`` exists because GeoIP is inference, not measurement: a
    result is often no better than country-level, and consumers that present
    coordinates as fact are lying to their users.
    """

    ip: str
    latitude: float
    longitude: float
    city: str | None = None
    region: str | None = None
    country: str | None = None
    country_code: str | None = None
    autonomous_system: str | None = None
    is_proxy: bool = False
    is_hosting: bool = False
    source: str = "unknown"
    accuracy_note: str = "city-level estimate; may be off by hundreds of km"

    @property
    def coordinates(self) -> tuple[float, float]:
        return (self.latitude, self.longitude)

    def describe(self) -> str:
        parts = [p for p in (self.city, self.region, self.country) if p]
        return ", ".join(parts) if parts else "unknown location"

    def to_json(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Hop:
    """One traceroute hop, aggregated over the probes sent for that TTL."""

    ttl: int
    kind: HopKind
    address: str | None = None
    hostname: str | None = None
    rtts_ms: tuple[float, ...] = ()
    sent: int = 0
    location: GeoLocation | None = None

    @property
    def received(self) -> int:
        return len(self.rtts_ms)

    @property
    def loss_pct(self) -> float:
        if self.sent == 0:
            return 0.0
        return 100.0 * (self.sent - self.received) / self.sent

    @property
    def best_ms(self) -> float | None:
        return min(self.rtts_ms) if self.rtts_ms else None

    @property
    def worst_ms(self) -> float | None:
        return max(self.rtts_ms) if self.rtts_ms else None

    @property
    def avg_ms(self) -> float | None:
        if not self.rtts_ms:
            return None
        return sum(self.rtts_ms) / len(self.rtts_ms)

    @property
    def jitter_ms(self) -> float | None:
        """Mean absolute difference between consecutive probes.

        Cheaper and more honest than a standard deviation for two or three
        samples, and it is what network engineers actually read a trace for.
        """
        if len(self.rtts_ms) < 2:
            return None
        deltas = [abs(b - a) for a, b in zip(self.rtts_ms, self.rtts_ms[1:], strict=False)]
        return sum(deltas) / len(deltas)

    @property
    def label(self) -> str:
        if self.address is None:
            return "*"
        if self.hostname and self.hostname != self.address:
            return f"{self.hostname} ({self.address})"
        return self.address

    def to_json(self) -> JsonDict:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["rtts_ms"] = list(self.rtts_ms)
        data["loss_pct"] = round(self.loss_pct, 1)
        data["avg_ms"] = self.avg_ms
        data["jitter_ms"] = self.jitter_ms
        return data


@dataclass(frozen=True, slots=True)
class TraceResult:
    """The outcome of a complete traceroute."""

    destination: str
    destination_ip: str
    hops: tuple[Hop, ...]
    completed: bool
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None

    @property
    def reached(self) -> bool:
        return any(hop.kind is HopKind.DESTINATION for hop in self.hops)

    @property
    def duration_s(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def to_json(self) -> JsonDict:
        return {
            "destination": self.destination,
            "destination_ip": self.destination_ip,
            "reached": self.reached,
            "completed": self.completed,
            "hops": [hop.to_json() for hop in self.hops],
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_s": self.duration_s,
        }


@dataclass(frozen=True, slots=True)
class HostRecord:
    """A host observed to be up during discovery."""

    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    open_ports: tuple[int, ...] = ()
    latency_ms: float | None = None
    location: GeoLocation | None = None
    distance_km: float | None = None

    @property
    def is_private(self) -> bool:
        try:
            return ipaddress.ip_address(self.ip).is_private
        except ValueError:
            return False

    def to_json(self) -> JsonDict:
        data = asdict(self)
        data["open_ports"] = list(self.open_ports)
        data["is_private"] = self.is_private
        return data


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """A single captured frame, reduced to the fields the UI displays.

    Deliberately *not* a scapy packet: holding live scapy objects in a GUI
    model keeps whole buffers alive and couples the view to the capture
    backend. Payloads are never retained.
    """

    timestamp: datetime
    protocol: Protocol
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    length: int = 0
    tcp_flags: str | None = None

    @property
    def summary(self) -> str:
        src = self.src_ip or self.src_mac or "?"
        dst = self.dst_ip or self.dst_mac or "?"
        if self.src_port is not None:
            src = f"{src}:{self.src_port}"
        if self.dst_port is not None:
            dst = f"{dst}:{self.dst_port}"
        flags = f" [{self.tcp_flags}]" if self.tcp_flags else ""
        return f"{self.protocol.value.upper()} {src} -> {dst}{flags} {self.length}B"

    def to_json(self) -> JsonDict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["protocol"] = self.protocol.value
        return data


@dataclass(frozen=True, slots=True)
class CaptureFilter:
    """User-facing capture criteria, compiled to BPF before capture starts.

    Filtering in the kernel rather than in Python is the difference between
    keeping up with a busy link and dropping most of it: an unfiltered
    ``sniff()`` copies every frame into userspace just to discard it.
    """

    protocol: Protocol | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None

    def is_empty(self) -> bool:
        return all(value in (None, "") for value in asdict(self).values())


@dataclass(frozen=True, slots=True)
class CaptureStats:
    """Counters describing a capture session."""

    captured: int = 0
    dropped_by_kernel: int | None = None
    bytes_seen: int = 0
    started_at: datetime = field(default_factory=_utcnow)

    def to_json(self) -> JsonDict:
        data = asdict(self)
        data["started_at"] = self.started_at.isoformat()
        return data


def to_json(value: Any) -> Any:
    """Recursively convert models (and containers of them) to JSON-safe data."""
    if hasattr(value, "to_json"):
        return value.to_json()
    if isinstance(value, Mapping):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, (str, bytes)):
        return value.decode() if isinstance(value, bytes) else value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (Sequence, Iterable)) and not isinstance(value, (str, bytes)):
        return [to_json(item) for item in value]
    return value
