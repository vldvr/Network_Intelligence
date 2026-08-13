"""Ports — the interfaces ``core`` depends on instead of concrete libraries.

Each protocol here is the seam where a real backend (scapy, nmap, an HTTP API)
is plugged in. ``core`` is written against these, so the domain logic can be
exercised in tests with in-memory fakes: no root, no network, no nmap binary,
deterministic timing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from netintel.models import HostRecord, PacketRecord


@runtime_checkable
class HttpClient(Protocol):
    """Minimal JSON-over-HTTP transport."""

    def get_json(
        self, url: str, *, params: Mapping[str, str] | None = None, timeout: float = 5.0
    ) -> Any: ...

    def post_json(self, url: str, *, payload: Any, timeout: float = 5.0) -> Any: ...


@runtime_checkable
class NameResolver(Protocol):
    """Forward and reverse DNS, isolated so tests never touch a resolver."""

    def resolve(self, hostname: str) -> str:
        """Return an IP address for ``hostname``."""

    def reverse(self, ip: str) -> str | None:
        """Return a PTR name for ``ip``, or ``None`` when there is none."""


@runtime_checkable
class ProbeSender(Protocol):
    """Sends one traceroute probe and reports what came back."""

    def send_probe(
        self, destination_ip: str, ttl: int, *, timeout: float, sequence: int
    ) -> ProbeReply | None:
        """Return the reply, or ``None`` if the probe timed out."""


class ProbeReply(Protocol):
    """What a router or the destination sent back.

    Declared as read-only properties rather than attributes so that an
    immutable implementation — the adapters return frozen dataclasses —
    satisfies the protocol. A bare ``source: str`` would demand a settable
    attribute and quietly exclude them.
    """

    @property
    def source(self) -> str: ...

    @property
    def rtt_ms(self) -> float: ...

    @property
    def is_destination(self) -> bool: ...

    @property
    def is_unreachable(self) -> bool: ...


@runtime_checkable
class DiscoveryBackend(Protocol):
    """Finds live hosts in an address range."""

    @property
    def name(self) -> str: ...

    def discover(
        self,
        targets: Sequence[str],
        *,
        timeout: float,
        should_continue: Callable[[], bool],
        on_host: Callable[[HostRecord], None] | None = None,
    ) -> Sequence[HostRecord]:
        """Return the hosts that answered.

        Implementations report each host through ``on_host`` as soon as it is
        found — a sweep of a /24 takes long enough that a front end must not
        have to wait for the whole run before showing anything.
        """


@runtime_checkable
class PacketSource(Protocol):
    """Yields decoded frames from an interface.

    Implementations must honour ``should_continue`` promptly and must not
    buffer frames beyond what is needed to decode one.
    """

    def interfaces(self) -> Sequence[str]: ...

    def capture(
        self,
        interface: str,
        *,
        bpf_filter: str | None,
        should_continue: Callable[[], bool],
    ) -> Iterator[PacketRecord]: ...


@runtime_checkable
class Clock(Protocol):
    """Time source, injected so rate limiting can be tested instantly."""

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...
