"""Shared fixtures and in-memory fakes.

Every backend is faked here, which is the point of the port/adapter split: the
whole suite runs without root, without a network, without nmap and without
PyQt5, and it runs in well under a second.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC
from typing import Any

import pytest

from netintel.models import HostRecord, PacketRecord, Protocol


class FakeClock:
    """Virtual clock — makes rate-limit tests instant and deterministic."""

    def __init__(self, start: float = 0.0) -> None:
        self.current = start
        self.slept: list[float] = []

    def now(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.current += seconds

    def advance(self, seconds: float) -> None:
        self.current += seconds


class FakeHttpClient:
    """Records requests and replays scripted responses."""

    def __init__(self, responses: Sequence[Any] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, str, Any]] = []

    def get_json(self, url: str, *, params: Any = None, timeout: float = 5.0) -> Any:
        self.calls.append(("GET", url, params))
        return self._next()

    def post_json(self, url: str, *, payload: Any, timeout: float = 5.0) -> Any:
        self.calls.append(("POST", url, payload))
        return self._next()

    def _next(self) -> Any:
        if not self.responses:
            raise AssertionError("FakeHttpClient ran out of scripted responses")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeResolver:
    def __init__(
        self, forward: dict[str, str] | None = None, reverse: dict[str, str] | None = None
    ) -> None:
        self.forward = forward or {}
        self.reverse_map = reverse or {}

    def resolve(self, hostname: str) -> str:
        from netintel.errors import TargetError

        try:
            return self.forward[hostname]
        except KeyError:
            raise TargetError(f"cannot resolve {hostname!r}") from None

    def reverse(self, ip: str) -> str | None:
        return self.reverse_map.get(ip)


@dataclass(frozen=True)
class FakeReply:
    source: str
    rtt_ms: float
    is_destination: bool = False
    is_unreachable: bool = False


class ScriptedProbeSender:
    """Returns a canned reply per TTL; ``None`` models a timeout."""

    def __init__(self, replies: dict[int, FakeReply | None]) -> None:
        self.replies = replies
        self.sent: list[tuple[str, int, int]] = []

    def send_probe(
        self, destination_ip: str, ttl: int, *, timeout: float, sequence: int
    ) -> FakeReply | None:
        self.sent.append((destination_ip, ttl, sequence))
        return self.replies.get(ttl)


class FakeDiscoveryBackend:
    name = "fake"

    def __init__(self, up: Sequence[str], *, fail_after: int | None = None) -> None:
        self.up = list(up)
        self.fail_after = fail_after
        self.requested: list[str] = []

    def discover(
        self,
        targets: Sequence[str],
        *,
        timeout: float,
        should_continue: Callable[[], bool],
        on_host: Callable[[HostRecord], None] | None = None,
    ) -> Sequence[HostRecord]:
        self.requested = list(targets)
        found: list[HostRecord] = []
        for ip in targets:
            if not should_continue():
                break
            if ip not in self.up:
                continue
            record = HostRecord(ip=ip, latency_ms=1.0)
            found.append(record)
            if on_host is not None:
                on_host(record)
        return found


class FakePacketSource:
    def __init__(self, packets: Sequence[PacketRecord]) -> None:
        self.packets = list(packets)
        self.filters: list[str | None] = []

    def interfaces(self) -> Sequence[str]:
        return ("eth0", "lo")

    def capture(
        self,
        interface: str,
        *,
        bpf_filter: str | None,
        should_continue: Callable[[], bool],
    ) -> Iterator[PacketRecord]:
        self.filters.append(bpf_filter)
        for packet in self.packets:
            if not should_continue():
                return
            yield packet


def make_packet(**overrides: Any) -> PacketRecord:
    from datetime import datetime

    defaults: dict[str, Any] = {
        "timestamp": datetime(2024, 1, 1, 12, 0, tzinfo=UTC),
        "protocol": Protocol.TCP,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 4444,
        "dst_port": 443,
        "length": 74,
    }
    defaults.update(overrides)
    return PacketRecord(**defaults)


def ip_api_entry(ip: str, lat: float, lon: float, **extra: Any) -> dict[str, Any]:
    """One successful ip-api batch entry."""
    entry = {
        "status": "success",
        "query": ip,
        "lat": lat,
        "lon": lon,
        "city": "London",
        "regionName": "England",
        "country": "United Kingdom",
        "countryCode": "GB",
        "as": "AS64500 Example",
    }
    entry.update(extra)
    return entry


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture(autouse=True)
def _reset_factory_state() -> Iterator[None]:
    from netintel.adapters.factory import reset_shared_state

    reset_shared_state()
    yield
    reset_shared_state()
