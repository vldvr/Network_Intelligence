"""Composition root.

Wiring lives in exactly one place. The CLI and the GUI both call these
functions, so the two front ends cannot drift into using different caching,
different quotas or different backend-selection rules.
"""

from __future__ import annotations

from netintel.core.geoip import (
    CachingGeoIPProvider,
    GeoIPProvider,
    IpApiProvider,
    NullGeoIPProvider,
)
from netintel.ports import DiscoveryBackend, NameResolver, PacketSource, ProbeSender

_shared_geoip: GeoIPProvider | None = None


def build_geoip_provider(*, offline: bool = False, shared: bool = True) -> GeoIPProvider:
    """Return a cached ip-api provider, or a no-op one when offline.

    The cache is process-wide by default so a trace and a scan in the same
    session share both the cached answers and the rate-limit budget.
    """
    global _shared_geoip

    if offline:
        return NullGeoIPProvider()

    if shared and _shared_geoip is not None:
        return _shared_geoip

    from netintel.adapters.http import RequestsHttpClient

    provider = CachingGeoIPProvider(IpApiProvider(RequestsHttpClient()))
    if shared:
        _shared_geoip = provider
    return provider


def build_resolver(*, enabled: bool = True) -> NameResolver:
    from netintel.adapters.dns import NullResolver, SystemResolver

    return SystemResolver() if enabled else NullResolver()


def build_probe_sender(*, interface: str | None = None) -> ProbeSender:
    from netintel.adapters.scapy_backend import ScapyProbeSender

    return ScapyProbeSender(interface=interface)


def build_packet_source() -> PacketSource:
    from netintel.adapters.scapy_backend import ScapyPacketSource

    return ScapyPacketSource()


def build_discovery_backend(*, prefer: str = "auto") -> DiscoveryBackend:
    """Pick a discovery backend.

    ``auto`` uses nmap when it is installed and falls back to the built-in TCP
    connect sweep otherwise — the tool stays usable on a machine where nmap
    was never installed, which is most machines.
    """
    from netintel.adapters.nmap_backend import NmapBackend
    from netintel.adapters.tcp import TcpConnectBackend

    if prefer == "nmap":
        return NmapBackend()
    if prefer == "tcp":
        return TcpConnectBackend()
    if prefer != "auto":
        raise ValueError(f"unknown discovery backend {prefer!r}")

    return NmapBackend() if NmapBackend.is_available() else TcpConnectBackend()


def reset_shared_state() -> None:
    """Drop the process-wide provider. Used by tests."""
    global _shared_geoip
    _shared_geoip = None
