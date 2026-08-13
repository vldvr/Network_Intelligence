"""Dependency-free host discovery over TCP connect().

The original tool could not start without nmap on ``PATH``, and nmap's ping
sweep needs root for anything but a plain connect scan. This backend needs
neither: it opens ordinary TCP sockets, so it runs unprivileged, on every
platform, in a container, in CI.

It is not a replacement for nmap — no ARP sweep, no OS fingerprinting — and
the factory still prefers nmap when it is available. It exists so the tool
degrades to something useful instead of to a stack trace.
"""

from __future__ import annotations

import errno
import socket
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed

from netintel.models import HostRecord

DEFAULT_PROBE_PORTS: tuple[int, ...] = (443, 80, 22, 445, 3389, 8080)
"""Ports likely to be listening *or* to be actively refused. Either answer
proves the host is up; only silence is ambiguous."""


class TcpConnectBackend:
    """Sweeps a range by attempting TCP connections."""

    name = "tcp-connect"

    def __init__(
        self,
        *,
        ports: Sequence[int] = DEFAULT_PROBE_PORTS,
        max_workers: int = 64,
    ) -> None:
        if not ports:
            raise ValueError("at least one probe port is required")
        self._ports = tuple(ports)
        self._max_workers = max(1, max_workers)

    def discover(
        self,
        targets: Sequence[str],
        *,
        timeout: float,
        should_continue: Callable[[], bool],
        on_host: Callable[[HostRecord], None] | None = None,
    ) -> Sequence[HostRecord]:
        found: list[HostRecord] = []
        if not targets:
            return found

        workers = min(self._max_workers, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._probe_host, ip, timeout, should_continue): ip for ip in targets
            }
            for future in as_completed(futures):
                record = future.result()
                if record is None:
                    continue
                found.append(record)
                if on_host is not None:
                    on_host(record)

        found.sort(key=lambda host: socket.inet_aton(host.ip) if _is_v4(host.ip) else host.ip)
        return found

    def _probe_host(
        self, ip: str, timeout: float, should_continue: Callable[[], bool]
    ) -> HostRecord | None:
        open_ports: list[int] = []
        latency_ms: float | None = None
        alive = False

        # Split the budget across ports so a host with several filtered ports
        # does not stall the sweep for (ports * timeout) seconds.
        per_port = max(0.05, timeout / len(self._ports))

        for port in self._ports:
            if not should_continue():
                break
            started = time.perf_counter()
            state = _probe_port(ip, port, per_port)
            elapsed_ms = (time.perf_counter() - started) * 1000.0

            if state is _PortState.OPEN:
                open_ports.append(port)
                alive = True
            elif state is _PortState.REFUSED:
                # A RST is proof of life even though nothing is listening.
                alive = True
            else:
                continue

            if latency_ms is None or elapsed_ms < latency_ms:
                latency_ms = elapsed_ms

        if not alive:
            return None
        return HostRecord(
            ip=ip,
            open_ports=tuple(open_ports),
            latency_ms=latency_ms,
        )


class _PortState:
    OPEN = "open"
    REFUSED = "refused"
    FILTERED = "filtered"


def _probe_port(ip: str, port: int, timeout: float) -> str:
    family = socket.AF_INET if _is_v4(ip) else socket.AF_INET6
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except TimeoutError:
            return _PortState.FILTERED
        except OSError as exc:
            if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                return _PortState.REFUSED
            return _PortState.FILTERED
        return _PortState.OPEN


def _is_v4(ip: str) -> bool:
    return ":" not in ip
