"""CLI tests.

``main`` returns an exit code and writes to a stream it is given, so these run
in-process — no subprocesses, no output parsing from a pipe.
"""

from __future__ import annotations

import io
import json

import pytest

from netintel.cli.main import EXIT_ERROR, EXIT_OK, build_parser, main
from netintel.core.geoip import CachingGeoIPProvider, IpApiProvider
from netintel.ratelimit import Quota, TokenBucket
from tests.conftest import (
    FakeClock,
    FakeDiscoveryBackend,
    FakeHttpClient,
    FakePacketSource,
    ip_api_entry,
    make_packet,
)


def run(argv):
    out = io.StringIO()
    code = main(argv, out=out)
    return code, out.getvalue()


def test_parser_builds():
    assert build_parser().prog == "netintel"


def test_version_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_scope_reports_the_default_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, output = run(["scope"])
    assert code == EXIT_OK
    assert "private address space only" in output


def test_scope_json_lists_the_allowed_prefixes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, output = run(["--json", "scope"])
    payload = json.loads(output)
    assert code == EXIT_OK
    assert "192.168.0.0/16" in payload["allowed"]
    assert payload["allow_public"] is False


def test_print_filter_compiles_without_touching_an_interface():
    code, output = run(["capture", "--print-filter", "--protocol", "tcp", "--dst-port", "443"])
    assert code == EXIT_OK
    assert output.strip() == "tcp and dst port 443"


def test_print_filter_reports_an_invalid_value():
    code, _ = run(["capture", "--print-filter", "--src-ip", "nope"])
    assert code == EXIT_ERROR


def test_geo_lookup(monkeypatch):
    http = FakeHttpClient([[ip_api_entry("8.8.8.8", 37.4, -122.1)]])
    provider = CachingGeoIPProvider(
        IpApiProvider(http, bucket=TokenBucket(Quota(100, 60.0), clock=FakeClock()))
    )
    monkeypatch.setattr("netintel.cli.main.build_geoip_provider", lambda **_: provider)

    code, output = run(["geo", "8.8.8.8"])
    assert code == EXIT_OK
    assert "London" in output
    assert "37.4000" in output


def test_geo_json_is_parseable(monkeypatch):
    http = FakeHttpClient([[ip_api_entry("8.8.8.8", 37.4, -122.1)]])
    provider = CachingGeoIPProvider(
        IpApiProvider(http, bucket=TokenBucket(Quota(100, 60.0), clock=FakeClock()))
    )
    monkeypatch.setattr("netintel.cli.main.build_geoip_provider", lambda **_: provider)

    code, output = run(["--json", "geo", "8.8.8.8"])
    payload = json.loads(output)
    assert code == EXIT_OK
    assert payload[0]["location"]["country_code"] == "GB"


def test_geo_offline_reports_no_location():
    code, output = run(["--offline", "geo", "8.8.8.8"])
    assert code == EXIT_OK
    assert "no location available" in output


def test_geo_with_near_reports_a_distance(monkeypatch):
    http = FakeHttpClient([[ip_api_entry("8.8.8.8", 48.8566, 2.3522)]])
    provider = CachingGeoIPProvider(
        IpApiProvider(http, bucket=TokenBucket(Quota(100, 60.0), clock=FakeClock()))
    )
    monkeypatch.setattr("netintel.cli.main.build_geoip_provider", lambda **_: provider)

    code, output = run(["geo", "8.8.8.8", "--near", "51.5074,-0.1278"])
    assert code == EXIT_OK
    assert "344 km away" in output  # London to Paris, rounded for display


def test_malformed_coordinate_is_a_handled_error():
    code, _ = run(["geo", "8.8.8.8", "--near", "north"])
    assert code == EXIT_ERROR


def test_discover_uses_the_selected_backend(monkeypatch):
    backend = FakeDiscoveryBackend(up=["192.168.1.4"])
    monkeypatch.setattr("netintel.cli.main.build_discovery_backend", lambda **_: backend)

    code, output = run(["--offline", "discover", "192.168.1.0/29"])
    assert code == EXIT_OK
    assert "192.168.1.4" in output


def test_discover_json_shape(monkeypatch):
    backend = FakeDiscoveryBackend(up=["192.168.1.4"])
    monkeypatch.setattr("netintel.cli.main.build_discovery_backend", lambda **_: backend)

    _, output = run(["--json", "--offline", "discover", "192.168.1.0/29"])
    payload = json.loads(output)
    assert payload["found"] == 1
    assert payload["hosts"][0]["ip"] == "192.168.1.4"


def test_discover_refuses_a_public_range_without_authorisation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backend = FakeDiscoveryBackend(up=["1.1.1.1"])
    monkeypatch.setattr("netintel.cli.main.build_discovery_backend", lambda **_: backend)

    code, _ = run(["--offline", "discover", "1.1.1.1"])
    assert code == EXIT_ERROR
    assert backend.requested == []


def test_discover_accepts_an_explicit_authorised_scope(monkeypatch):
    backend = FakeDiscoveryBackend(up=["203.0.113.5"])
    monkeypatch.setattr("netintel.cli.main.build_discovery_backend", lambda **_: backend)

    code, output = run(
        [
            "--offline",
            "discover",
            "203.0.113.0/29",
            "--authorized-scope",
            "203.0.113.0/24",
        ]
    )
    assert code == EXIT_OK
    assert "203.0.113.5" in output


def test_near_without_radius_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "netintel.cli.main.build_discovery_backend", lambda **_: FakeDiscoveryBackend(up=[])
    )
    code, _ = run(["discover", "192.168.1.0/29", "--near", "51.5,0.1"])
    assert code == EXIT_ERROR


def test_capture_writes_lines(monkeypatch):
    source = FakePacketSource([make_packet(), make_packet(length=120)])
    monkeypatch.setattr("netintel.cli.main.build_packet_source", lambda: source)

    code, output = run(["capture", "-i", "eth0"])
    assert code == EXIT_OK
    assert output.count("TCP 10.0.0.1:4444 -> 10.0.0.2:443") == 2
    assert "2 packet(s)" in output


def test_capture_list_interfaces(monkeypatch):
    monkeypatch.setattr("netintel.cli.main.build_packet_source", lambda: FakePacketSource([]))
    code, output = run(["capture", "--list-interfaces"])
    assert code == EXIT_OK
    assert "eth0" in output


def test_capture_without_an_interface_explains_the_options(monkeypatch):
    monkeypatch.setattr("netintel.cli.main.build_packet_source", lambda: FakePacketSource([]))
    code, _ = run(["capture"])
    assert code == EXIT_ERROR


def test_capture_count_limit(monkeypatch):
    source = FakePacketSource([make_packet() for _ in range(10)])
    monkeypatch.setattr("netintel.cli.main.build_packet_source", lambda: source)

    code, output = run(["--json", "capture", "-i", "eth0", "-c", "3"])
    payload = json.loads(output)
    assert code == EXIT_OK
    assert len(payload["packets"]) == 3
