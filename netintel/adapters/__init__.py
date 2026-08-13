"""Adapters — the concrete implementations of the ports.

Every optional dependency is imported *inside* a function or method here, and
a failure to import is translated into
:class:`netintel.errors.BackendUnavailableError` with a hint the user can act
on. That keeps ``import netintel`` cheap and total: the CLI's ``geo`` command
works on a machine with no scapy, no nmap and no PyQt5 installed.
"""

from netintel.adapters.dns import SystemResolver
from netintel.adapters.factory import (
    build_discovery_backend,
    build_geoip_provider,
    build_packet_source,
    build_probe_sender,
)
from netintel.adapters.http import RequestsHttpClient
from netintel.adapters.tcp import TcpConnectBackend

__all__ = [
    "RequestsHttpClient",
    "SystemResolver",
    "TcpConnectBackend",
    "build_discovery_backend",
    "build_geoip_provider",
    "build_packet_source",
    "build_probe_sender",
]
