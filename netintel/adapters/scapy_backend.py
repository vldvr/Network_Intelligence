"""scapy-backed probing and capture.

scapy is imported lazily: it is slow to import (it builds protocol tables and
reads the routing table at import time) and it is not needed by the CLI's
lookup commands. Paying ~1.5 s of import cost for ``netintel geo 1.1.1.1``
would be a poor trade.
"""

from __future__ import annotations

import contextlib
import queue
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from netintel.errors import BackendUnavailableError, PrivilegeError
from netintel.models import PacketRecord, Protocol

_SCAPY_HINT = "install it with `pip install scapy`"
_PRIVILEGE_HINT = (
    "raw sockets need elevated privileges: run with sudo, or on Linux grant "
    "the interpreter CAP_NET_RAW (`sudo setcap cap_net_raw,cap_net_admin+eip "
    "$(readlink -f $(which python3))`)"
)

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_TIME_EXCEEDED = 11


def _import_scapy() -> Any:
    try:
        from scapy import all as scapy_all
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise BackendUnavailableError("scapy", _SCAPY_HINT) from exc
    return scapy_all


@dataclass(frozen=True, slots=True)
class ScapyProbeReply:
    """Concrete :class:`netintel.ports.ProbeReply`."""

    source: str
    rtt_ms: float
    is_destination: bool
    is_unreachable: bool


class ScapyProbeSender:
    """ICMP echo probes with an increasing TTL.

    Each probe carries a distinct identifier and sequence number so a reply
    can be matched to the probe that caused it. The original code sent bare
    ``ICMP()`` packets with default fields, which means concurrent traces (or
    another ping on the box) could be credited to the wrong hop.
    """

    def __init__(self, *, interface: str | None = None) -> None:
        self._interface = interface
        self._identifier = int(time.time()) & 0xFFFF

    def send_probe(
        self, destination_ip: str, ttl: int, *, timeout: float, sequence: int
    ) -> ScapyProbeReply | None:
        scapy = _import_scapy()

        packet = scapy.IP(dst=destination_ip, ttl=ttl) / scapy.ICMP(
            id=self._identifier, seq=(ttl << 8 | sequence) & 0xFFFF
        )

        started = time.perf_counter()
        try:
            reply = scapy.sr1(packet, verbose=0, timeout=timeout, iface=self._interface)
        except PermissionError as exc:
            raise PrivilegeError(_PRIVILEGE_HINT) from exc
        except OSError as exc:
            if getattr(exc, "errno", None) in (1, 13):  # EPERM / EACCES
                raise PrivilegeError(_PRIVILEGE_HINT) from exc
            raise
        rtt_ms = (time.perf_counter() - started) * 1000.0

        if reply is None:
            return None

        icmp_type = getattr(reply.getlayer(scapy.ICMP), "type", None)
        return ScapyProbeReply(
            source=str(reply.src),
            rtt_ms=rtt_ms,
            is_destination=(icmp_type == ICMP_ECHO_REPLY or str(reply.src) == destination_ip),
            is_unreachable=icmp_type == ICMP_DEST_UNREACHABLE,
        )


class ScapyPacketSource:
    """Live capture via scapy's :class:`AsyncSniffer`.

    ``sniff()`` blocks and only evaluates ``stop_filter`` when a frame
    arrives, so on a quiet interface a stop request hangs until the next
    packet — exactly the "the Stop button does nothing" bug in the original.
    ``AsyncSniffer`` plus a bounded queue makes stopping immediate and gives
    the consumer a generator to pull from.

    The queue is bounded on purpose: if the consumer cannot keep up, dropping
    frames at the queue is the honest outcome. Growing without limit would
    trade a visible gap in the capture for an invisible memory leak.
    """

    def __init__(self, *, queue_size: int = 4096, poll_interval_s: float = 0.2) -> None:
        self._queue_size = queue_size
        self._poll = poll_interval_s

    def interfaces(self) -> Sequence[str]:
        scapy = _import_scapy()
        return tuple(scapy.get_if_list())

    def capture(
        self,
        interface: str,
        *,
        bpf_filter: str | None,
        should_continue: Callable[[], bool],
    ) -> Iterator[PacketRecord]:
        scapy = _import_scapy()
        pending: queue.Queue[PacketRecord] = queue.Queue(maxsize=self._queue_size)

        def enqueue(packet: Any) -> None:
            # Consumer is behind: drop rather than grow the queue unbounded.
            with contextlib.suppress(queue.Full):
                pending.put_nowait(decode_packet(packet, scapy))

        sniffer = scapy.AsyncSniffer(iface=interface, filter=bpf_filter, prn=enqueue, store=False)
        try:
            sniffer.start()
        except PermissionError as exc:
            raise PrivilegeError(_PRIVILEGE_HINT) from exc
        except OSError as exc:
            if getattr(exc, "errno", None) in (1, 13):
                raise PrivilegeError(_PRIVILEGE_HINT) from exc
            raise

        try:
            while should_continue():
                try:
                    yield pending.get(timeout=self._poll)
                except queue.Empty:
                    continue
        finally:
            # Always stop the sniffer, including when the consumer abandons
            # the generator early: a leaked AsyncSniffer keeps a raw socket
            # and a thread alive for the life of the process.
            with contextlib.suppress(Exception):  # best-effort teardown
                sniffer.stop()


def decode_packet(packet: Any, scapy: Any) -> PacketRecord:
    """Reduce a scapy packet to a :class:`PacketRecord`.

    Payload bytes are intentionally dropped. Capturing traffic already carries
    a duty of care; retaining and rendering payloads in a GUI turns a
    diagnostic tool into a credential harvester by accident.
    """
    ip_layer = packet.getlayer(scapy.IP) or packet.getlayer(scapy.IPv6)
    ether = packet.getlayer(scapy.Ether)
    tcp = packet.getlayer(scapy.TCP)
    udp = packet.getlayer(scapy.UDP)
    icmp = packet.getlayer(scapy.ICMP)

    if tcp is not None:
        protocol = Protocol.TCP
    elif udp is not None:
        protocol = Protocol.UDP
    elif icmp is not None:
        protocol = Protocol.ICMP
    else:
        protocol = Protocol.OTHER

    transport = tcp if tcp is not None else udp
    timestamp = getattr(packet, "time", None)
    when = datetime.fromtimestamp(float(timestamp), tz=UTC) if timestamp else datetime.now(UTC)

    return PacketRecord(
        timestamp=when,
        protocol=protocol,
        src_ip=str(ip_layer.src) if ip_layer is not None else None,
        dst_ip=str(ip_layer.dst) if ip_layer is not None else None,
        src_port=int(transport.sport) if transport is not None else None,
        dst_port=int(transport.dport) if transport is not None else None,
        src_mac=str(ether.src) if ether is not None else None,
        dst_mac=str(ether.dst) if ether is not None else None,
        length=len(packet),
        tcp_flags=str(tcp.flags) if tcp is not None else None,
    )
