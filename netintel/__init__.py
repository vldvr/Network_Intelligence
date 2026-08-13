"""NetworkIntelligence — network diagnostics toolkit.

The package is split into three layers:

``netintel.core``
    Pure-Python domain logic. Knows nothing about Qt and nothing about the
    concrete libraries used to put packets on the wire — those arrive through
    the protocols declared in :mod:`netintel.ports`.

``netintel.cli``
    A scriptable front end. Emits human-readable text or JSON.

``netintel.ui``
    A thin PyQt5 front end. Contains presentation code only; every long
    running operation is delegated to ``core`` on a worker thread.

Importing this package must never pull in PyQt5, scapy or nmap. Backends are
imported lazily by the adapters in :mod:`netintel.adapters` so that the CLI
and the test suite run without the GUI stack installed.
"""

from netintel.errors import (
    BackendUnavailableError,
    GeoIPError,
    NetIntelError,
    ScopeViolationError,
    TargetError,
)
from netintel.models import (
    CaptureFilter,
    GeoLocation,
    Hop,
    HostRecord,
    PacketRecord,
    TraceResult,
)

__version__ = "1.0.0"

__all__ = [
    "BackendUnavailableError",
    "CaptureFilter",
    "GeoIPError",
    "GeoLocation",
    "Hop",
    "HostRecord",
    "NetIntelError",
    "PacketRecord",
    "ScopeViolationError",
    "TargetError",
    "TraceResult",
    "__version__",
]
