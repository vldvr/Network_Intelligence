"""Discovery service: policy, and enrichment."""

from __future__ import annotations

import pytest

from netintel.cancellation import CancellationToken
from netintel.core.discovery import (
    DiscoveryConfig,
    DiscoveryService,
    format_report,
)
from netintel.core.geoip import CachingGeoIPProvider, IpApiProvider
from netintel.core.scope import ScopePolicy
from netintel.errors import ScopeViolationError, TargetError
from netintel.ratelimit import Quota, TokenBucket
from tests.conftest import (
    FakeClock,
    FakeDiscoveryBackend,
    FakeHttpClient,
    ip_api_entry,
)

LONDON = (51.5074, -0.1278)
PARIS_ENTRY = ("198.51.100.2", 48.8566, 2.3522)
LONDON_ENTRY = ("198.51.100.1", 51.5074, -0.1278)


def geoip(entries):
    http = FakeHttpClient([[ip_api_entry(ip, lat, lon) for ip, lat, lon in entries]])
    provider = IpApiProvider(http, bucket=TokenBucket(Quota(100, 60.0), clock=FakeClock()))
    return CachingGeoIPProvider(provider), http


def test_only_responding_hosts_are_reported():
    backend = FakeDiscoveryBackend(up=["192.168.1.5", "192.168.1.9"])
    service = DiscoveryService(backend)

    report = service.discover("192.168.1.0/29")

    assert [host.ip for host in report.hosts] == ["192.168.1.5"]
    assert report.requested == 6


def test_scope_is_checked_before_any_packet_is_sent():
    backend = FakeDiscoveryBackend(up=["8.8.8.8"])
    service = DiscoveryService(backend, policy=ScopePolicy.private_only())

    with pytest.raises(ScopeViolationError):
        service.discover("8.8.8.8")

    assert backend.requested == [], "the backend must never have been called"


def test_authorised_public_scope_is_allowed_through():
    backend = FakeDiscoveryBackend(up=["203.0.113.5"])
    service = DiscoveryService(backend, policy=ScopePolicy.from_prefixes(["203.0.113.0/24"]))
    report = service.discover("203.0.113.0/29")
    assert [host.ip for host in report.hosts] == ["203.0.113.5"]


def test_hosts_stream_to_the_callback():
    backend = FakeDiscoveryBackend(up=["192.168.1.1", "192.168.1.2"])
    seen = []
    DiscoveryService(backend).discover("192.168.1.1-2", on_host=seen.append)
    assert [host.ip for host in seen] == ["192.168.1.1", "192.168.1.2"]


def test_cancellation_produces_a_partial_report():
    token = CancellationToken()
    backend = FakeDiscoveryBackend(up=[f"192.168.1.{n}" for n in range(1, 20)])
    service = DiscoveryService(backend)

    def stop_after_first(host):
        token.cancel()

    report = service.discover("192.168.1.0/24", token=token, on_host=stop_after_first)
    assert report.cancelled is True
    assert len(report.hosts) == 1


def test_geolocation_enriches_the_results():
    provider, _ = geoip([LONDON_ENTRY])
    service = DiscoveryService(
        FakeDiscoveryBackend(up=["198.51.100.1"]),
        policy=ScopePolicy.from_prefixes(["198.51.100.0/24"]),
        geoip=provider,
    )
    report = service.discover("198.51.100.1", config=DiscoveryConfig(geolocate=True))
    assert report.hosts[0].location is not None
    assert report.hosts[0].location.city == "London"


def test_geolocation_without_a_provider_is_a_clear_error():
    service = DiscoveryService(FakeDiscoveryBackend(up=[]))
    with pytest.raises(TargetError, match="no provider is configured"):
        service.discover("192.168.1.1", config=DiscoveryConfig(geolocate=True))


def test_invalid_timeout_is_rejected():
    with pytest.raises(TargetError):
        DiscoveryConfig(timeout_s=0.0).validated()


def test_report_renders_a_readable_summary():
    backend = FakeDiscoveryBackend(up=["192.168.1.1"])
    report = DiscoveryService(backend).discover("192.168.1.0/29")
    text = format_report(report)
    assert "192.168.1.1" in text
    assert "1 host(s) responded" in text


def test_report_serialises_to_json():
    backend = FakeDiscoveryBackend(up=["192.168.1.1"])
    payload = DiscoveryService(backend).discover("192.168.1.0/29").to_json()
    assert payload["found"] == 1
    assert payload["hosts"][0]["ip"] == "192.168.1.1"
    assert payload["hosts"][0]["is_private"] is True
