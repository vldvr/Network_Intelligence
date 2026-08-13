"""BPF compilation and capture session behaviour."""

from __future__ import annotations

import pytest

from netintel.cancellation import CancellationToken
from netintel.core.capture import CaptureSession, compile_bpf, format_packet
from netintel.errors import TargetError
from netintel.models import CaptureFilter, Protocol
from tests.conftest import FakePacketSource, make_packet


def test_empty_filter_compiles_to_nothing():
    assert compile_bpf(CaptureFilter()) is None


def test_protocol_filter():
    assert compile_bpf(CaptureFilter(protocol=Protocol.TCP)) == "tcp"


def test_terms_are_combined_with_and():
    expression = compile_bpf(CaptureFilter(protocol=Protocol.UDP, src_ip="10.0.0.1", dst_port=53))
    assert expression == "udp and src host 10.0.0.1 and dst port 53"


def test_mac_filters_are_normalised():
    expression = compile_bpf(CaptureFilter(src_mac="AA:BB:CC:DD:EE:FF"))
    assert expression == "ether src aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "criteria",
    [
        CaptureFilter(src_ip="not-an-ip"),
        CaptureFilter(dst_ip="10.0.0.256"),
        CaptureFilter(src_port=0),
        CaptureFilter(dst_port=70000),
        CaptureFilter(src_port="eighty"),
        CaptureFilter(src_mac="zz:zz:zz:zz:zz:zz"),
        CaptureFilter(dst_mac="aa-bb-cc-dd-ee-ff"),
    ],
)
def test_invalid_criteria_never_reach_the_compiler(criteria):
    with pytest.raises(TargetError):
        compile_bpf(criteria)


@pytest.mark.parametrize(
    "hostile",
    [
        "10.0.0.1 or not tcp",
        "10.0.0.1) and (udp",
        "10.0.0.1; drop",
    ],
)
def test_filter_expressions_cannot_be_injected_through_an_address(hostile):
    """Values are parsed as addresses, so extra BPF syntax cannot ride along."""
    with pytest.raises(TargetError):
        compile_bpf(CaptureFilter(src_ip=hostile))


def test_session_yields_packets_and_counts_them():
    packets = [make_packet(length=100), make_packet(length=40)]
    session = CaptureSession(source=FakePacketSource(packets), interface="eth0")

    captured = list(session.stream())

    assert len(captured) == 2
    assert session.stats.captured == 2
    assert session.stats.bytes_seen == 140


def test_session_passes_the_compiled_filter_to_the_source():
    source = FakePacketSource([make_packet()])
    session = CaptureSession(
        source=source, interface="eth0", criteria=CaptureFilter(protocol=Protocol.TCP)
    )
    list(session.stream())
    assert source.filters == ["tcp"]


def test_max_packets_stops_the_capture():
    source = FakePacketSource([make_packet() for _ in range(10)])
    session = CaptureSession(source=source, interface="eth0", max_packets=3)
    assert len(list(session.stream())) == 3


def test_cancellation_stops_the_capture():
    token = CancellationToken()
    source = FakePacketSource([make_packet() for _ in range(10)])
    session = CaptureSession(source=source, interface="eth0")

    captured = []
    for packet in session.stream(token=token):
        captured.append(packet)
        token.cancel()

    assert len(captured) == 1


def test_buffer_is_bounded():
    """An unbounded buffer behind a live capture is a timed memory leak."""
    source = FakePacketSource([make_packet() for _ in range(100)])
    session = CaptureSession(source=source, interface="eth0", buffer_size=10)
    list(session.stream())

    assert session.stats.captured == 100
    assert len(session.packets) == 10


def test_zero_buffer_is_rejected():
    with pytest.raises(TargetError):
        CaptureSession(source=FakePacketSource([]), interface="eth0", buffer_size=0)


def test_packet_summary_and_formatting():
    packet = make_packet(src_port=1234, dst_port=443, tcp_flags="S")
    assert "10.0.0.1:1234 -> 10.0.0.2:443" in packet.summary
    assert format_packet(packet).startswith("12:00:00.000")


def test_packet_serialises_to_json():
    payload = make_packet().to_json()
    assert payload["protocol"] == "tcp"
    assert payload["timestamp"].startswith("2024-01-01T12:00:00")
