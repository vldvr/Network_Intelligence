"""Traceroute.

Rewritten from the original single-probe ICMP loop. What is different:

* **RTT is measured.** A traceroute that prints hop addresses without
  round-trip times cannot answer the question people run traceroute to
  answer — where the latency appears.
* **Several probes per hop**, so loss and jitter at a hop are visible rather
  than a hop being declared dead on one dropped packet.
* **Early exit on a filtered path.** The original always walked 30 TTLs;
  against a firewall that drops ICMP that is 30 timeouts back to back. After
  a run of silent hops the trace gives up and says so.
* **Reverse DNS is cached and optional.** ``gethostbyaddr`` per hop, on the
  worker thread, with the system resolver timeout, was most of the wall-clock
  time of a trace against unresolvable routers.
* **Results stream out.** Hops are handed to a callback as they complete, so
  a front end can render the trace as it happens instead of after it ends.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from netintel.cancellation import NEVER_CANCELLED, CancellationToken
from netintel.core.geoip import GeoIPProvider
from netintel.core.targets import is_hostname, parse_address
from netintel.errors import TargetError
from netintel.models import Hop, HopKind, TraceResult
from netintel.ports import NameResolver, ProbeSender

HopCallback = Callable[[Hop], None]


@dataclass(frozen=True, slots=True)
class TraceConfig:
    """Tunables for a trace. Defaults match what ``traceroute(8)`` does."""

    max_hops: int = 30
    probes_per_hop: int = 3
    timeout_s: float = 2.0
    resolve_names: bool = True
    geolocate: bool = False
    give_up_after_silent_hops: int = 5
    """Abandon the trace after this many consecutive fully silent hops."""

    def validated(self) -> TraceConfig:
        if not 1 <= self.max_hops <= 255:
            raise TargetError("max_hops must be between 1 and 255")
        if not 1 <= self.probes_per_hop <= 10:
            raise TargetError("probes_per_hop must be between 1 and 10")
        if not 0.1 <= self.timeout_s <= 30.0:
            raise TargetError("timeout must be between 0.1 and 30 seconds")
        return self


class Tracer:
    """Traces the path to a destination using an injected probe sender."""

    def __init__(
        self,
        sender: ProbeSender,
        resolver: NameResolver,
        *,
        geoip: GeoIPProvider | None = None,
        config: TraceConfig | None = None,
    ) -> None:
        self._sender = sender
        self._resolver = resolver
        self._geoip = geoip
        self._config = (config or TraceConfig()).validated()
        self._ptr_cache: dict[str, str | None] = {}

    @property
    def config(self) -> TraceConfig:
        return self._config

    def trace(
        self,
        destination: str,
        *,
        token: CancellationToken = NEVER_CANCELLED,
        on_hop: HopCallback | None = None,
    ) -> TraceResult:
        """Run a trace to ``destination`` (an IP literal or a hostname)."""
        started_at = datetime.now(UTC)
        destination_ip = self._resolve_destination(destination)

        hops: list[Hop] = []
        completed = False
        silent_run = 0

        for ttl in range(1, self._config.max_hops + 1):
            if token.cancelled:
                break

            hop = self._probe_hop(destination_ip, ttl, token=token)
            hops.append(hop)
            if on_hop is not None:
                on_hop(hop)

            if hop.kind is HopKind.DESTINATION:
                completed = True
                break
            if hop.kind is HopKind.UNREACHABLE:
                completed = True
                break

            silent_run = silent_run + 1 if hop.kind is HopKind.TIMEOUT else 0
            if silent_run >= self._config.give_up_after_silent_hops:
                break

        if self._config.geolocate and self._geoip is not None:
            hops = self._attach_locations(hops, token=token)

        return TraceResult(
            destination=destination,
            destination_ip=destination_ip,
            hops=tuple(hops),
            completed=completed,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

    def _resolve_destination(self, destination: str) -> str:
        candidate = destination.strip()
        if not candidate:
            raise TargetError("no destination specified")
        if is_hostname(candidate):
            return self._resolver.resolve(candidate)
        return str(parse_address(candidate))

    def _probe_hop(self, destination_ip: str, ttl: int, *, token: CancellationToken) -> Hop:
        rtts: list[float] = []
        address: str | None = None
        kind = HopKind.TIMEOUT
        sent = 0

        for sequence in range(self._config.probes_per_hop):
            if token.cancelled:
                break
            sent += 1
            reply = self._sender.send_probe(
                destination_ip,
                ttl,
                timeout=self._config.timeout_s,
                sequence=sequence,
            )
            if reply is None:
                continue

            rtts.append(reply.rtt_ms)
            # Keep the first responder: ECMP means later probes for the same
            # TTL can legitimately come back from a different router, and
            # overwriting makes the path look like it is flapping.
            if address is None:
                address = reply.source
            if reply.is_destination:
                kind = HopKind.DESTINATION
            elif reply.is_unreachable and kind is not HopKind.DESTINATION:
                kind = HopKind.UNREACHABLE
            elif kind is HopKind.TIMEOUT:
                kind = HopKind.ROUTER

        hostname = self._reverse(address) if address else None
        return Hop(
            ttl=ttl,
            kind=kind,
            address=address,
            hostname=hostname,
            rtts_ms=tuple(rtts),
            sent=sent,
        )

    def _reverse(self, address: str) -> str | None:
        if not self._config.resolve_names:
            return None
        if address not in self._ptr_cache:
            self._ptr_cache[address] = self._resolver.reverse(address)
        return self._ptr_cache[address]

    def _attach_locations(self, hops: Sequence[Hop], *, token: CancellationToken) -> list[Hop]:
        assert self._geoip is not None
        addresses = [hop.address for hop in hops if hop.address]
        if not addresses:
            return list(hops)
        located = self._geoip.lookup_many(addresses, token=token)
        return [
            replace(hop, location=located.get(hop.address)) if hop.address else hop for hop in hops
        ]


def format_hop(hop: Hop) -> str:
    """One line per hop, in the layout ``traceroute(8)`` users already read."""
    if hop.kind is HopKind.TIMEOUT:
        return f"{hop.ttl:>2}  * * *"

    times = "  ".join(f"{rtt:.2f} ms" for rtt in hop.rtts_ms) or "no reply"
    line = f"{hop.ttl:>2}  {hop.label}  {times}"
    if hop.loss_pct:
        line += f"  ({hop.loss_pct:.0f}% loss)"
    if hop.kind is HopKind.UNREACHABLE:
        line += "  !unreachable"
    if hop.location is not None:
        line += f"  [{hop.location.describe()}]"
    return line


def format_trace(result: TraceResult) -> str:
    """Render a complete trace as text, header and footer included."""
    header = (
        f"traceroute to {result.destination} ({result.destination_ip}), "
        f"{len(result.hops)} hops recorded"
    )
    body = "\n".join(format_hop(hop) for hop in result.hops)
    if result.reached:
        footer = f"destination reached in {len(result.hops)} hops"
    elif result.completed:
        footer = "path terminated before the destination (unreachable)"
    else:
        footer = "trace ended without reaching the destination"
    return "\n".join(part for part in (header, body, footer) if part)
