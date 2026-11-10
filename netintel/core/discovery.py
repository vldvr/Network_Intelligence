"""Host discovery, plus optional geographic enrichment.

The original scanner did three things in one 90-line method on a widget:
shelled out to nmap, geolocated each result one at a time with a 1.5 s sleep
between calls, and appended strings to a ``QTextEdit`` from a worker thread.

Here the three concerns are separated. The backend finds hosts; this service
applies policy (scope, limits) and enriches results in batch.
Nothing in this module knows a UI exists.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from netintel.cancellation import NEVER_CANCELLED, CancellationToken
from netintel.core.geoip import GeoIPProvider
from netintel.core.scope import ScopePolicy
from netintel.core.targets import DEFAULT_MAX_HOSTS, parse_targets
from netintel.errors import TargetError
from netintel.models import HostRecord
from netintel.ports import DiscoveryBackend

HostCallback = Callable[[HostRecord], None]


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Tunables for a discovery run."""

    timeout_s: float = 1.0
    max_hosts: int = DEFAULT_MAX_HOSTS
    geolocate: bool = False

    def validated(self) -> DiscoveryConfig:
        if not 0.1 <= self.timeout_s <= 30.0:
            raise TargetError("timeout must be between 0.1 and 30 seconds")
        return self

    @property
    def needs_geoip(self) -> bool:
        return self.geolocate


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """Everything a caller needs to describe what a scan did."""

    expression: str
    requested: int
    hosts: tuple[HostRecord, ...]
    cancelled: bool = False
    backend: str = "unknown"

    def to_json(self) -> dict[str, object]:
        return {
            "expression": self.expression,
            "requested": self.requested,
            "found": len(self.hosts),
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
        if settings.needs_geoip and hosts:
            hosts = self._enrich(hosts, token=token)

        return DiscoveryReport(
            expression=spec.raw,
            requested=len(spec),
            hosts=tuple(hosts),
            cancelled=token.cancelled,
            backend=getattr(self._backend, "name", "unknown"),
        )

    def _enrich(self, hosts: Sequence[HostRecord], *, token: CancellationToken) -> list[HostRecord]:
        assert self._geoip is not None
        located = self._geoip.lookup_many([host.ip for host in hosts], token=token)
        return [replace(host, location=located.get(host.ip)) for host in hosts]


def format_report(report: DiscoveryReport) -> str:
    """Render a discovery report as an aligned text table."""
    lines = [
        f"scanned {report.requested} address(es) from {report.expression!r} via {report.backend}",
        f"{len(report.hosts)} host(s) responded",
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
        lines.append("  ".join(parts).rstrip())
    return "\n".join(lines)
