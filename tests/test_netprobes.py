"""Standard-library probes against throwaway servers on 127.0.0.1."""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from netintel.adapters.netprobes import WireDnsClient, fetch_headers, scan_ports, system_nameserver
from netintel.core.dnswire import DnsError, encode_name
from netintel.errors import TargetError


def _answer(query: bytes, *, truncated: bool = False, rcode: int = 0) -> bytes:
    qid = struct.unpack_from("!H", query)[0]
    question = query[12:]
    flags = 0x8180 | (0x0200 if truncated else 0) | rcode
    if truncated or rcode:
        return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + question
    rdata = struct.pack("!H", 10) + encode_name("mx.example.com")
    record = b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 60, len(rdata)) + rdata
    return struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0) + question + record


class FakeDns:
    """Answers on UDP and TCP of the same port; can truncate UDP answers."""

    def __init__(self, *, truncate_udp: bool = False, rcode: int = 0) -> None:
        self.truncate_udp, self.rcode = truncate_udp, rcode
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen()
        self.tcp_queries = 0
        for target in (self._serve_udp, self._serve_tcp):
            threading.Thread(target=target, daemon=True).start()

    def _serve_udp(self) -> None:
        while True:
            try:
                data, addr = self.udp.recvfrom(512)
            except OSError:
                return
            self.udp.sendto(_answer(data, truncated=self.truncate_udp, rcode=self.rcode), addr)

    def _serve_tcp(self) -> None:
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            with conn:
                (size,) = struct.unpack("!H", conn.recv(2))
                reply = _answer(conn.recv(size), rcode=self.rcode)
                self.tcp_queries += 1
                conn.sendall(struct.pack("!H", len(reply)) + reply)

    def close(self) -> None:
        self.udp.close()
        self.tcp.close()


@pytest.fixture
def dns_client() -> Iterator:
    servers: list[FakeDns] = []

    def make(**kwargs):
        server = FakeDns(**kwargs)
        servers.append(server)
        return WireDnsClient("127.0.0.1", port=server.port, timeout=1.0), server

    yield make
    for server in servers:
        server.close()


def test_udp_query_returns_parsed_records(dns_client):
    client, server = dns_client()
    records = client.query("example.com", "MX")
    assert [r.value for r in records] == ["10 mx.example.com"]
    assert server.tcp_queries == 0


def test_truncated_udp_answer_is_retried_over_tcp(dns_client):
    client, server = dns_client(truncate_udp=True)
    assert client.query("example.com", "MX")[0].value == "10 mx.example.com"
    assert server.tcp_queries == 1


def test_nxdomain_is_an_empty_answer_and_servfail_an_error(dns_client):
    client, _ = dns_client(rcode=3)
    assert client.query("missing.example.com", "A") == []
    client, _ = dns_client(rcode=2)
    with pytest.raises(DnsError, match="SERVFAIL"):
        client.txt("example.com")


def test_system_nameserver_reads_resolv_conf(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("# comment\nnameserver fe80::1\nnameserver 192.0.2.53\n")
    assert system_nameserver(conf) == "192.0.2.53"
    assert system_nameserver(tmp_path / "missing") == "1.1.1.1"


# ---------------------------------------------------------------- HTTP


class _Handler(BaseHTTPRequestHandler):
    server_version = "demo/1.0"

    def do_GET(self) -> None:
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/new")
        else:
            self.send_response(200)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "a=1")
            self.send_header("Set-Cookie", "b=2")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def http_server() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_fetch_follows_redirects_and_keeps_duplicate_headers(http_server):
    obs = fetch_headers(f"{http_server}/old")
    assert obs.url.endswith("/new")
    assert obs.status == 200
    assert not obs.https
    assert obs.get("x-content-type-options") == "nosniff"
    assert obs.get_all("Set-Cookie") == ["a=1", "b=2"]


def test_fetch_from_a_closed_port_is_a_target_error():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(TargetError):
        fetch_headers(f"http://127.0.0.1:{port}/", timeout=1.0)


# --------------------------------------------------------------- ports


def test_scan_ports_finds_listeners_and_grabs_banners():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    open_port = listener.getsockname()[1]

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")

    threading.Thread(target=serve, daemon=True).start()
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]

    seen = []
    found = scan_ports(
        ["127.0.0.1"],
        [open_port, closed_port],
        timeout=1.0,
        should_continue=lambda: True,
        on_open=seen.append,
    )
    listener.close()

    assert [(p.port, p.service) for p in found] == [(open_port, "ssh")]
    assert seen == found


def test_scan_ports_stops_when_cancelled():
    assert scan_ports(["127.0.0.1"], [1, 2, 3], timeout=0.2, should_continue=lambda: False) == []


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("https://example.com/", "file:///etc/passwd"),
        ("https://example.com/", "http://example.com/"),
        ("https://example.com/", "https://127.0.0.1/admin"),
    ],
)
def test_dangerous_redirects_are_refused(current, target, monkeypatch):
    from netintel.adapters import netprobes

    monkeypatch.setattr(netprobes, "_is_local_host", lambda host: host == "127.0.0.1")
    with pytest.raises(TargetError):
        netprobes._check_redirect(current, target)


def test_local_to_local_redirects_are_allowed(http_server):
    assert fetch_headers(f"{http_server}/old").status == 200
