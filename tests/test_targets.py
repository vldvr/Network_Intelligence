"""Target parsing — the boundary where untrusted input becomes addresses."""

from __future__ import annotations

import ipaddress

import pytest

from netintel.core.targets import (
    is_hostname,
    is_public,
    parse_address,
    parse_targets,
    summarise,
)
from netintel.errors import TargetError


def test_single_address():
    spec = parse_targets("192.168.1.10")
    assert spec.as_strings == ("192.168.1.10",)


def test_cidr_excludes_network_and_broadcast():
    spec = parse_targets("192.168.1.0/29")
    assert spec.as_strings == tuple(f"192.168.1.{n}" for n in range(1, 7))


def test_slash_32_yields_the_host_itself():
    assert parse_targets("10.1.2.3/32").as_strings == ("10.1.2.3",)


def test_dash_range():
    spec = parse_targets("10.0.0.5-8")
    assert spec.as_strings == ("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8")


def test_mixed_list_deduplicates_and_keeps_order():
    spec = parse_targets("10.0.0.1, 10.0.0.1 10.0.0.2")
    assert spec.as_strings == ("10.0.0.1", "10.0.0.2")


def test_ipv6_is_supported():
    assert parse_targets("2001:db8::1").as_strings == ("2001:db8::1",)


def test_reversed_dash_range_is_rejected():
    with pytest.raises(TargetError, match="range start"):
        parse_targets("10.0.0.40-10")


def test_oversized_range_is_refused():
    with pytest.raises(TargetError, match="more than"):
        parse_targets("10.0.0.0/8", max_hosts=1024)


def test_empty_expression_is_refused():
    with pytest.raises(TargetError):
        parse_targets("   ")


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", "10.0.0.1/999", ""])
def test_malformed_input_raises_target_error(bad):
    with pytest.raises(TargetError):
        parse_targets(bad)


def test_shorthand_addresses_are_rejected():
    """``socket.inet_aton`` would read this as 10.0.0.1 — a different host."""
    with pytest.raises(TargetError):
        parse_address("10.1")


def test_shell_metacharacters_never_parse():
    with pytest.raises(TargetError):
        parse_targets("127.0.0.1; rm -rf /")


@pytest.mark.parametrize(
    "address,public",
    [
        ("8.8.8.8", True),
        ("192.168.1.1", False),
        ("10.0.0.1", False),
        ("172.16.5.4", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("224.0.0.1", False),
        ("fd00::1", False),
        ("fe80::1", False),
        ("2606:4700::1111", True),
        # Carrier-grade NAT reaches other people's devices, so it must not be
        # treated as local even though ``ipaddress`` calls it private.
        ("100.64.0.1", True),
    ],
)
def test_public_classification(address, public):
    assert is_public(ipaddress.ip_address(address)) is public


@pytest.mark.parametrize(
    "text,expected",
    [
        ("example.com", True),
        ("a.b.c.example.com", True),
        ("192.168.1.1", False),
        ("-bad.example.com", False),
        ("", False),
    ],
)
def test_hostname_detection(text, expected):
    assert is_hostname(text) is expected


def test_summarise_truncates():
    spec = parse_targets("10.0.0.1-9")
    assert "+6 more" in summarise(spec.addresses)
