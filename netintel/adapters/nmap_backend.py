"""Host discovery via nmap, through ``python-nmap``.

Two behavioural fixes over the original use of this library:

* Targets are passed as an explicit list of validated addresses rather than
  as a raw user string. ``python-nmap`` builds an nmap command line from that
  argument, so it is the wrong place to forward unparsed input.
* Hosts are reported as they are found. The original waited for the whole
  sweep to finish, so a /24 showed nothing at all for a minute and then
  everything at once.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from netintel.errors import BackendUnavailableError, NetIntelError
from netintel.models import HostRecord

_NMAP_HINT = (
    "install the nmap binary (macOS: `brew install nmap`, Debian/Ubuntu: "
    "`apt install nmap`) and the bindings with `pip install python-nmap`"
)

_CHUNK_SIZE = 256
"""Addresses per nmap invocation — small enough that partial results arrive
promptly, large enough that process start-up is not the dominant cost."""


class NmapBackend:
    """Ping-sweep backend built on nmap."""

    name = "nmap"

    def __init__(self, *, extra_arguments: str = "-sn -n") -> None:
        # -n disables nmap's own DNS resolution: it is slow, and this codebase
        # resolves names itself where a name is actually wanted.
        self._arguments = extra_arguments

    @staticmethod
    def is_available() -> bool:
        try:
            scanner = _import_nmap().PortScanner()
        except (BackendUnavailableError, Exception):
            return False
        return scanner is not None

    def discover(
        self,
        targets: Sequence[str],
        *,
        timeout: float,
        should_continue: Callable[[], bool],
        on_host: Callable[[HostRecord], None] | None = None,
    ) -> Sequence[HostRecord]:
        nmap = _import_nmap()
        try:
            scanner = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            raise BackendUnavailableError("nmap", _NMAP_HINT) from exc

        found: list[HostRecord] = []
        for chunk in _chunks(targets, _CHUNK_SIZE):
            if not should_continue():
                break
            for record in self._scan_chunk(scanner, nmap, chunk):
                found.append(record)
                if on_host is not None:
                    on_host(record)
        return found

    def _scan_chunk(self, scanner: Any, nmap: Any, chunk: Sequence[str]) -> list[HostRecord]:
        try:
            scanner.scan(hosts=" ".join(chunk), arguments=self._arguments)
        except nmap.PortScannerError as exc:
            raise NetIntelError(f"nmap failed: {exc}") from exc

        records: list[HostRecord] = []
        for ip in scanner.all_hosts():
            host = scanner[ip]
            if host.state() != "up":
                continue
            records.append(
                HostRecord(
                    ip=ip,
                    hostname=_first_hostname(host),
                    mac=host.get("addresses", {}).get("mac"),
                    vendor=next(iter(host.get("vendor", {}).values()), None),
                    latency_ms=_latency_ms(host),
                )
            )
        return records


def _first_hostname(host: Any) -> str | None:
    for entry in host.get("hostnames", []):
        name = entry.get("name")
        if name:
            return str(name)
    return None


def _latency_ms(host: Any) -> float | None:
    """Smoothed round-trip time, when nmap reported one.

    ``times.srtt`` is in microseconds and is absent for hosts found by ARP, so
    a missing or unparseable value is simply "unknown" rather than an error.
    """
    try:
        return float(host.get("times", {}).get("srtt", "")) / 1000.0
    except (TypeError, ValueError):
        return None


def _import_nmap() -> Any:
    try:
        import nmap
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise BackendUnavailableError("nmap", _NMAP_HINT) from exc
    return nmap


def _chunks(items: Sequence[str], size: int) -> list[Sequence[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
