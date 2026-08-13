"""The dependency-free discovery backend, against real loopback sockets."""

from __future__ import annotations

import socket
import threading

import pytest

from netintel.adapters.tcp import TcpConnectBackend


@pytest.fixture
def listening_port():
    """A real listening socket on loopback."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]

    stop = threading.Event()

    def accept_loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            connection.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(timeout=2)
    server.close()


def test_finds_a_host_with_an_open_port(listening_port):
    backend = TcpConnectBackend(ports=[listening_port])
    hosts = backend.discover(["127.0.0.1"], timeout=1.0, should_continue=lambda: True)

    assert [host.ip for host in hosts] == ["127.0.0.1"]
    assert hosts[0].open_ports == (listening_port,)
    assert hosts[0].latency_ms is not None


def test_a_refused_connection_still_proves_the_host_is_up():
    """A RST answers the liveness question even with nothing listening."""
    closed = _unused_port()
    backend = TcpConnectBackend(ports=[closed])
    hosts = backend.discover(["127.0.0.1"], timeout=1.0, should_continue=lambda: True)

    assert [host.ip for host in hosts] == ["127.0.0.1"]
    assert hosts[0].open_ports == ()


def test_hosts_are_streamed_as_they_are_found(listening_port):
    seen = []
    TcpConnectBackend(ports=[listening_port]).discover(
        ["127.0.0.1"], timeout=1.0, should_continue=lambda: True, on_host=seen.append
    )
    assert len(seen) == 1


def test_cancellation_is_honoured(listening_port):
    backend = TcpConnectBackend(ports=[listening_port])
    hosts = backend.discover(["127.0.0.1"], timeout=1.0, should_continue=lambda: False)
    assert hosts == []


def test_empty_target_list_is_a_no_op():
    assert TcpConnectBackend().discover([], timeout=1.0, should_continue=lambda: True) == []


def test_at_least_one_port_is_required():
    with pytest.raises(ValueError):
        TcpConnectBackend(ports=[])


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
