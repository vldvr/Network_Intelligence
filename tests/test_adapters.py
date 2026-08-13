"""Adapter tests.

The adapters are where untyped third-party objects are translated into domain
models, so they carry real logic and are worth testing — but not by installing
scapy and nmap in CI and hoping for a root shell. Each library is replaced by
a fake module at the single lazy-import seam, which is exactly the boundary
the adapters were written to have.
"""

from __future__ import annotations

import socket

import pytest

from netintel.adapters import factory
from netintel.adapters.dns import NullResolver, SystemResolver
from netintel.adapters.http import RequestsHttpClient
from netintel.errors import GeoIPError, PrivilegeError, TargetError
from netintel.models import Protocol
from netintel.privileges import check_raw_socket_privileges

# --------------------------------------------------------------- HTTP client


class FakeResponse:
    def __init__(self, status_code=200, payload=None, malformed=False):
        self.status_code = status_code
        self._payload = payload
        self._malformed = malformed

    def json(self):
        if self._malformed:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_get_json_returns_the_payload():
    session = FakeSession([FakeResponse(payload={"ok": True})])
    client = RequestsHttpClient(session=session, retries=0)
    assert client.get_json("http://example.test") == {"ok": True}


def test_post_json_sends_the_body():
    session = FakeSession([FakeResponse(payload=[])])
    client = RequestsHttpClient(session=session, retries=0)
    client.post_json("http://example.test", payload=[{"query": "1.1.1.1"}])
    assert session.requests[0][2]["json"] == [{"query": "1.1.1.1"}]


def test_server_errors_are_retried():
    session = FakeSession([FakeResponse(status_code=500), FakeResponse(payload={"ok": 1})])
    client = RequestsHttpClient(session=session, retries=1, backoff_s=0.0)
    assert client.get_json("http://example.test") == {"ok": 1}
    assert len(session.requests) == 2


def test_rate_limiting_is_retried():
    session = FakeSession([FakeResponse(status_code=429), FakeResponse(payload={"ok": 1})])
    client = RequestsHttpClient(session=session, retries=1, backoff_s=0.0)
    assert client.get_json("http://example.test") == {"ok": 1}


def test_client_errors_are_not_retried():
    """Repeating a request the server already rejected earns a longer ban."""
    session = FakeSession([FakeResponse(status_code=403), FakeResponse(payload={"ok": 1})])
    client = RequestsHttpClient(session=session, retries=3, backoff_s=0.0)
    with pytest.raises(GeoIPError, match="HTTP 403"):
        client.get_json("http://example.test")
    assert len(session.requests) == 1


def test_exhausted_retries_raise():
    session = FakeSession([FakeResponse(status_code=503), FakeResponse(status_code=503)])
    client = RequestsHttpClient(session=session, retries=1, backoff_s=0.0)
    with pytest.raises(GeoIPError):
        client.get_json("http://example.test")


def test_malformed_json_is_a_domain_error():
    session = FakeSession([FakeResponse(malformed=True)])
    client = RequestsHttpClient(session=session, retries=0)
    with pytest.raises(GeoIPError, match="malformed JSON"):
        client.get_json("http://example.test")


# ------------------------------------------------------------------- resolver


def test_resolver_prefers_ipv4(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET6, None, None, "", ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET, None, None, "", ("93.184.216.34", 0)),
        ],
    )
    assert SystemResolver().resolve("example.com") == "93.184.216.34"


def test_resolution_failure_is_a_domain_error(monkeypatch):
    def boom(*args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(TargetError, match="cannot resolve"):
        SystemResolver().resolve("nope.invalid")


def test_reverse_lookup_failure_returns_none(monkeypatch):
    def boom(ip):
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", boom)
    assert SystemResolver().reverse("10.0.0.1") is None


def test_reverse_lookup_returns_the_name(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("gw.example", [], [ip]))
    assert SystemResolver().reverse("10.0.0.1") == "gw.example"


def test_null_resolver_refuses_forward_lookups():
    with pytest.raises(TargetError):
        NullResolver().resolve("example.com")
    assert NullResolver().reverse("10.0.0.1") is None


# ---------------------------------------------------------------- privileges


def test_root_is_reported_as_privileged(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    status = check_raw_socket_privileges()
    assert status.available is True
    assert status.hint == ""


def test_missing_privileges_come_with_an_actionable_hint(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)

    def refuse(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(socket, "socket", refuse)
    status = check_raw_socket_privileges()
    assert status.available is False
    assert status.hint


# --------------------------------------------------------------------- scapy


class FakeLayerType:
    """Stands in for a scapy layer class used as a lookup key."""

    def __init__(self, name):
        self.name = name

    def __call__(self, **fields):
        return FakePacket(fields=fields)


class FakePacket:
    def __init__(self, layers=None, fields=None, src=None, size=64, time=None):
        self.layers = layers or {}
        self.fields = fields or {}
        self.src = src
        self._size = size
        self.time = time

    def getlayer(self, layer_type):
        return self.layers.get(layer_type)

    def __truediv__(self, other):
        return self

    def __len__(self):
        return self._size


class FakeScapy:
    def __init__(self, reply=None, packets=()):
        self.IP = FakeLayerType("IP")
        self.IPv6 = FakeLayerType("IPv6")
        self.ICMP = FakeLayerType("ICMP")
        self.TCP = FakeLayerType("TCP")
        self.UDP = FakeLayerType("UDP")
        self.Ether = FakeLayerType("Ether")
        self._reply = reply
        self._packets = list(packets)
        self.sent = []
        self.sniffer = None

    def sr1(self, packet, **kwargs):
        self.sent.append(kwargs)
        if isinstance(self._reply, Exception):
            raise self._reply
        return self._reply

    def get_if_list(self):
        return ["eth0", "lo"]

    def AsyncSniffer(self, **kwargs):
        self.sniffer = FakeSniffer(kwargs, self._packets)
        return self.sniffer


class FakeSniffer:
    def __init__(self, kwargs, packets):
        self.kwargs = kwargs
        self.packets = packets
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        for packet in self.packets:
            self.kwargs["prn"](packet)

    def stop(self):
        self.stopped = True


def icmp_reply(scapy, src, icmp_type):
    layer = FakePacket()
    layer.type = icmp_type
    return FakePacket(layers={scapy.ICMP: layer}, src=src)


def test_probe_reply_at_the_destination(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy()
    scapy._reply = icmp_reply(scapy, "93.184.216.34", scapy_backend.ICMP_ECHO_REPLY)
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)

    reply = scapy_backend.ScapyProbeSender().send_probe("93.184.216.34", 5, timeout=1.0, sequence=0)
    assert reply is not None
    assert reply.is_destination is True
    assert reply.rtt_ms >= 0


def test_probe_reply_from_an_intermediate_router(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy()
    scapy._reply = icmp_reply(scapy, "10.0.0.1", scapy_backend.ICMP_TIME_EXCEEDED)
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)

    reply = scapy_backend.ScapyProbeSender().send_probe("93.184.216.34", 2, timeout=1.0, sequence=0)
    assert reply.is_destination is False
    assert reply.is_unreachable is False


def test_probe_reply_unreachable(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy()
    scapy._reply = icmp_reply(scapy, "10.0.0.1", scapy_backend.ICMP_DEST_UNREACHABLE)
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)

    reply = scapy_backend.ScapyProbeSender().send_probe("93.184.216.34", 2, timeout=1.0, sequence=0)
    assert reply.is_unreachable is True


def test_probe_timeout_returns_none(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy(reply=None)
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)
    assert (
        scapy_backend.ScapyProbeSender().send_probe("1.2.3.4", 1, timeout=0.1, sequence=0) is None
    )


def test_permission_errors_become_a_privilege_error(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy(reply=PermissionError("nope"))
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)

    with pytest.raises(PrivilegeError, match="raw sockets"):
        scapy_backend.ScapyProbeSender().send_probe("1.2.3.4", 1, timeout=0.1, sequence=0)


def test_decode_packet_extracts_the_fields():
    from netintel.adapters.scapy_backend import decode_packet

    scapy = FakeScapy()
    ip = FakePacket()
    ip.src, ip.dst = "10.0.0.1", "10.0.0.2"
    tcp = FakePacket()
    tcp.sport, tcp.dport, tcp.flags = 1234, 443, "S"
    ether = FakePacket()
    ether.src, ether.dst = "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"

    packet = FakePacket(layers={scapy.IP: ip, scapy.TCP: tcp, scapy.Ether: ether}, size=74)
    record = decode_packet(packet, scapy)

    assert record.protocol is Protocol.TCP
    assert record.src_ip == "10.0.0.1"
    assert record.dst_port == 443
    assert record.src_mac == "aa:bb:cc:dd:ee:ff"
    assert record.length == 74
    assert record.tcp_flags == "S"


def test_decode_packet_without_a_transport_layer():
    from netintel.adapters.scapy_backend import decode_packet

    scapy = FakeScapy()
    ip = FakePacket()
    ip.src, ip.dst = "10.0.0.1", "10.0.0.2"
    record = decode_packet(FakePacket(layers={scapy.IP: ip}), scapy)

    assert record.protocol is Protocol.OTHER
    assert record.src_port is None


def test_capture_yields_packets_and_stops_the_sniffer(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy()
    ip = FakePacket()
    ip.src, ip.dst = "10.0.0.1", "10.0.0.2"
    udp = FakePacket()
    udp.sport, udp.dport = 5353, 53
    scapy._packets = [FakePacket(layers={scapy.IP: ip, scapy.UDP: udp}) for _ in range(3)]
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)

    source = scapy_backend.ScapyPacketSource(poll_interval_s=0.01)
    collected = []
    for record in source.capture("eth0", bpf_filter="udp", should_continue=lambda: True):
        collected.append(record)
        if len(collected) == 3:
            break

    assert len(collected) == 3
    assert collected[0].protocol is Protocol.UDP
    assert scapy.sniffer.kwargs["filter"] == "udp"
    assert scapy.sniffer.stopped is True, "abandoning the generator must release the socket"


def test_capture_stops_when_told_to(monkeypatch):
    from netintel.adapters import scapy_backend

    scapy = FakeScapy()
    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: scapy)
    source = scapy_backend.ScapyPacketSource(poll_interval_s=0.01)
    assert list(source.capture("eth0", bpf_filter=None, should_continue=lambda: False)) == []


def test_interface_listing(monkeypatch):
    from netintel.adapters import scapy_backend

    monkeypatch.setattr(scapy_backend, "_import_scapy", lambda: FakeScapy())
    assert scapy_backend.ScapyPacketSource().interfaces() == ("eth0", "lo")


# ---------------------------------------------------------------------- nmap


class FakeHost(dict):
    def __init__(self, state="up", **data):
        super().__init__(data)
        self._state = state

    def state(self):
        return self._state


class FakePortScanner:
    def __init__(self, hosts):
        self._hosts = hosts
        self.scanned = []

    def scan(self, hosts, arguments):
        self.scanned.append((hosts, arguments))

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, ip):
        return self._hosts[ip]


class FakeNmapModule:
    class PortScannerError(Exception):
        pass

    def __init__(self, scanner):
        self._scanner = scanner

    def PortScanner(self):
        return self._scanner


def test_nmap_backend_reports_only_hosts_that_are_up(monkeypatch):
    from netintel.adapters import nmap_backend

    scanner = FakePortScanner(
        {
            "192.168.1.1": FakeHost(
                hostnames=[{"name": "gw.lan"}],
                addresses={"mac": "aa:bb:cc:dd:ee:ff"},
                vendor={"aa:bb:cc:dd:ee:ff": "Acme"},
            ),
            "192.168.1.2": FakeHost(state="down"),
        }
    )
    monkeypatch.setattr(nmap_backend, "_import_nmap", lambda: FakeNmapModule(scanner))

    hosts = nmap_backend.NmapBackend().discover(
        ["192.168.1.1", "192.168.1.2"], timeout=1.0, should_continue=lambda: True
    )

    assert [host.ip for host in hosts] == ["192.168.1.1"]
    assert hosts[0].hostname == "gw.lan"
    assert hosts[0].vendor == "Acme"


def test_nmap_backend_disables_the_libraries_own_dns(monkeypatch):
    from netintel.adapters import nmap_backend

    scanner = FakePortScanner({})
    monkeypatch.setattr(nmap_backend, "_import_nmap", lambda: FakeNmapModule(scanner))
    nmap_backend.NmapBackend().discover(["192.168.1.1"], timeout=1.0, should_continue=lambda: True)
    assert scanner.scanned[0][1] == "-sn -n"


def test_nmap_backend_honours_cancellation(monkeypatch):
    from netintel.adapters import nmap_backend

    scanner = FakePortScanner({})
    monkeypatch.setattr(nmap_backend, "_import_nmap", lambda: FakeNmapModule(scanner))
    nmap_backend.NmapBackend().discover(["192.168.1.1"], timeout=1.0, should_continue=lambda: False)
    assert scanner.scanned == []


# ------------------------------------------------------------------- factory


def test_offline_factory_returns_the_null_provider():
    from netintel.core.geoip import NullGeoIPProvider

    assert isinstance(factory.build_geoip_provider(offline=True), NullGeoIPProvider)


def test_geoip_provider_is_shared_across_callers():
    """A shared cache means a trace and a scan draw on one quota, not two."""
    first = factory.build_geoip_provider()
    assert factory.build_geoip_provider() is first


def test_unshared_provider_is_distinct():
    assert factory.build_geoip_provider(shared=False) is not factory.build_geoip_provider(
        shared=False
    )


def test_discovery_backend_falls_back_when_nmap_is_absent(monkeypatch):
    from netintel.adapters.nmap_backend import NmapBackend
    from netintel.adapters.tcp import TcpConnectBackend

    monkeypatch.setattr(NmapBackend, "is_available", staticmethod(lambda: False))
    assert isinstance(factory.build_discovery_backend(), TcpConnectBackend)


def test_discovery_backend_prefers_nmap_when_present(monkeypatch):
    from netintel.adapters.nmap_backend import NmapBackend

    monkeypatch.setattr(NmapBackend, "is_available", staticmethod(lambda: True))
    assert isinstance(factory.build_discovery_backend(), NmapBackend)


def test_unknown_backend_name_is_rejected():
    with pytest.raises(ValueError):
        factory.build_discovery_backend(prefer="telepathy")
