"""Host discovery, plus optional geographic enrichment.

The original scanner did three things in one 90-line method on a widget:
shelled out to nmap, geolocated each result one at a time with a 1.5 s sleep
between calls, and appended strings to a ``QTextEdit`` from a worker thread.

Here the three concerns are separated. The backend finds hosts; this service
applies policy (scope, limits), enriches results in batch and filters them.
Nothing in this module knows a UI exists.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from netintel.cancellation import NEVER_CANCELLED, CancellationToken
from netintel.core.geoip import GeoIPProvider, haversine_km
from netintel.core.scope import ScopePolicy
from netintel.core.targets import DEFAULT_MAX_HOSTS, parse_targets
from netintel.errors import TargetError
from netintel.models import HostRecord
from netintel.ports import DiscoveryBackend

HostCallback = Callable[[HostRecord], None]


@dataclass(frozen=True, slots=True)
class GeoFilter:
    """Keep only hosts within ``max_distance_km`` of a reference point."""

    latitude: float
    longitude: float
    max_distance_km: float

    def validated(self) -> GeoFilter:
        if not -90.0 <= self.latitude <= 90.0:
            raise TargetError("latitude must be between -90 and 90")
        if not -180.0 <= self.longitude <= 180.0:
            raise TargetError("longitude must be between -180 and 180")
        if self.max_distance_km <= 0:
            raise TargetError("maximum distance must be positive")
        return self

    @property
    def origin(self) -> tuple[float, float]:
        return (self.latitude, self.longitude)


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Tunables for a discovery run."""

    timeout_s: float = 1.0
    max_hosts: int = DEFAULT_MAX_HOSTS
    geolocate: bool = False
    geo_filter: GeoFilter | None = None

    def validated(self) -> DiscoveryConfig:
        if not 0.1 <= self.timeout_s <= 30.0:
            raise TargetError("timeout must be between 0.1 and 30 seconds")
        if self.geo_filter is not None:
            self.geo_filter.validated()
        return self

    @property
    def needs_geoip(self) -> bool:
        return self.geolocate or self.geo_filter is not None


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """Everything a caller needs to describe what a scan did."""

    expression: str
    requested: int
    hosts: tuple[HostRecord, ...]
    filtered_out: int = 0
    cancelled: bool = False
    backend: str = "unknown"

    def to_json(self) -> dict[str, object]:
        return {
            "expression": self.expression,
            "requested": self.requested,
            "found": len(self.hosts),
            "filtered_out": self.filtered_out,
            "cancelled": self.cancelled,
            "backend": self.backend,
            "hosts": [host.to_json() for host in self.hosts],
        }


class DiscoveryService:
    """Runs discovery under a scope policy and enriches the results."""

    def __init__(
        self,
        backend: DiscoveryBackend,
        *,
        policy: ScopePolicy | None = None,
        geoip: GeoIPProvider | None = None,
    ) -> None:
        self._backend = backend
        self._policy = policy or ScopePolicy.private_only()
        self._geoip = geoip

    @property
    def policy(self) -> ScopePolicy:
        return self._policy

    def discover(
        self,
        expression: str,
        *,
        config: DiscoveryConfig | None = None,
        token: CancellationToken = NEVER_CANCELLED,
        on_host: HostCallback | None = None,
    ) -> DiscoveryReport:
        """Sweep ``expression`` and return the hosts that answered.

        Raises :class:`netintel.errors.ScopeViolationError` before a single
        packet is sent if any address falls outside the authorised scope.
        """
        settings = (config or DiscoveryConfig()).validated()
        spec = parse_targets(expression, max_hosts=settings.max_hosts)
        self._policy.check(spec)

        if settings.needs_geoip and self._geoip is None:
            raise TargetError("geolocation was requested but no provider is configured")

        found = self._backend.discover(
            spec.as_strings,
            timeout=settings.timeout_s,
            should_continue=token.should_continue,
            on_host=on_host,
        )

        hosts = list(found)
        filtered_out = 0
        if settings.needs_geoip and hosts:
            hosts, filtered_out = self._enrich(hosts, settings, token=token)

        return DiscoveryReport(
            expression=spec.raw,
            requested=len(spec),
            hosts=tuple(hosts),
            filtered_out=filtered_out,
            cancelled=token.cancelled,
            backend=getattr(self._backend, "name", "unknown"),
        )

    def _enrich(
        self,
        hosts: Sequence[HostRecord],
        config: DiscoveryConfig,
        *,
        token: CancellationToken,
    ) -> tuple[list[HostRecord], int]:
        assert self._geoip is not None
        located = self._geoip.lookup_many([host.ip for host in hosts], token=token)

        enriched: list[HostRecord] = []
        dropped = 0
        for host in hosts:
            location = located.get(host.ip)
            distance = None
            if location is not None and config.geo_filter is not None:
                distance = haversine_km(config.geo_filter.origin, location.coordinates)

            record = replace(host, location=location, distance_km=distance)
            # A host with no location cannot be shown to be within the radius,
            # so it is excluded rather than silently assumed to be near.
            if config.geo_filter is not None and (
                distance is None or distance > config.geo_filter.max_distance_km
            ):
                dropped += 1
                continue
            enriched.append(record)

        enriched.sort(key=lambda h: (h.distance_km is None, h.distance_km or 0.0))
        return enriched, dropped


def format_report(report: DiscoveryReport) -> str:
    """Render a discovery report as an aligned text table."""
    lines = [
        f"scanned {report.requested} address(es) from {report.expression!r} via {report.backend}",
        f"{len(report.hosts)} host(s) responded"
        + (f", {report.filtered_out} filtered out by distance" if report.filtered_out else ""),
    ]
    if report.cancelled:
        lines.append("run was cancelled before completion; results are partial")

    for host in report.hosts:
        parts = [f"  {host.ip:<39}"]
        if host.hostname:
            parts.append(host.hostname)
        if host.latency_ms is not None:
            parts.append(f"{host.latency_ms:.1f} ms")
        if host.open_ports:
            parts.append("ports " + ",".join(str(p) for p in host.open_ports))
        if host.location is not None:
            parts.append(host.location.describe())
        if host.distance_km is not None:
            parts.append(f"{host.distance_km:.0f} km")
        lines.append("  ".join(parts).rstrip())
    return "\n".join(lines)
