"""Geolocation: batching, caching, quota handling and hostile payloads."""

from __future__ import annotations

import pytest

from netintel.cancellation import CancellationToken
from netintel.core.geoip import (
    CachingGeoIPProvider,
    IpApiProvider,
    NullGeoIPProvider,
    haversine_km,
)
from netintel.errors import GeoIPError
from netintel.ratelimit import Quota, TokenBucket
from tests.conftest import FakeClock, FakeHttpClient, ip_api_entry


def make_provider(responses, *, clock=None):
    http = FakeHttpClient(responses)
    bucket = TokenBucket(Quota(1000, 60.0), clock=clock or FakeClock())
    return IpApiProvider(http, bucket=bucket), http


def test_single_lookup():
    provider, _ = make_provider([[ip_api_entry("1.1.1.1", 51.5, -0.12)]])
    location = provider.lookup("1.1.1.1")
    assert location is not None
    assert location.city == "London"
    assert location.coordinates == (51.5, -0.12)


def test_lookups_are_batched_into_one_request():
    ips = [f"203.0.113.{n}" for n in range(1, 51)]
    provider, http = make_provider([[ip_api_entry(ip, 1.0, 2.0) for ip in ips]])

    results = provider.lookup_many(ips)

    assert len(http.calls) == 1, "50 addresses must cost one request, not 50"
    assert all(results[ip] is not None for ip in ips)


def test_batches_are_split_at_the_provider_limit():
    ips = [f"203.0.113.{n}" for n in range(1, 151)]
    provider, http = make_provider(
        [
            [ip_api_entry(ip, 1.0, 2.0) for ip in ips[:100]],
            [ip_api_entry(ip, 1.0, 2.0) for ip in ips[100:]],
        ]
    )
    provider.lookup_many(ips)
    assert len(http.calls) == 2


def test_private_addresses_are_never_sent_to_the_provider():
    provider, http = make_provider([])
    results = provider.lookup_many(["192.168.1.1", "10.0.0.1", "127.0.0.1"])
    assert http.calls == []
    assert all(value is None for value in results.values())


def test_mixed_input_only_queries_the_public_addresses():
    provider, http = make_provider([[ip_api_entry("8.8.8.8", 37.0, -122.0)]])
    results = provider.lookup_many(["192.168.1.1", "8.8.8.8"])
    assert http.calls[0][2] == [{"query": "8.8.8.8", "fields": IpApiProvider._FIELDS}]
    assert results["192.168.1.1"] is None
    assert results["8.8.8.8"] is not None


def test_failed_entries_are_reported_as_no_location():
    provider, _ = make_provider(
        [[{"status": "fail", "message": "reserved range", "query": "8.8.8.8"}]]
    )
    assert provider.lookup("8.8.8.8") is None


@pytest.mark.parametrize(
    "payload",
    [
        {"not": "a list"},
        None,
        "unexpected string",
    ],
)
def test_unexpected_payload_shape_raises_a_domain_error(payload):
    provider, _ = make_provider([payload])
    with pytest.raises(GeoIPError):
        provider.lookup("8.8.8.8")


@pytest.mark.parametrize(
    "entry",
    [
        {"status": "success", "query": "8.8.8.8"},  # no coordinates
        {"status": "success", "query": "8.8.8.8", "lat": "north", "lon": 1.0},
        {"status": "success", "lat": 1.0, "lon": 2.0},  # no query echo
        ["not", "a", "mapping"],
    ],
)
def test_malformed_entries_are_discarded_not_trusted(entry):
    """The provider is unauthenticated HTTP; its output is untrusted input."""
    provider, _ = make_provider([[entry]])
    assert provider.lookup("8.8.8.8") is None


def test_transport_failure_becomes_a_domain_error():
    provider, _ = make_provider([ConnectionError("network unreachable")])
    with pytest.raises(GeoIPError, match="geolocation request failed"):
        provider.lookup("8.8.8.8")


def test_cancellation_stops_before_the_next_batch():
    token = CancellationToken()
    ips = [f"203.0.113.{n}" for n in range(1, 151)]
    provider, http = make_provider([[ip_api_entry(ip, 1.0, 2.0) for ip in ips[:100]]])

    class CancellingBucket(TokenBucket):
        def acquire(self, cost=1.0, *, token=token):
            token.cancel() if http.calls else None
            return super().acquire(cost, token=token)

    provider._bucket = CancellingBucket(Quota(1000, 60.0), clock=FakeClock())
    provider.lookup_many(ips, token=token)
    assert len(http.calls) == 1


# --------------------------------------------------------------------- cache


def test_cache_serves_repeat_lookups_without_a_second_request():
    inner, http = make_provider([[ip_api_entry("8.8.8.8", 37.0, -122.0)]])
    clock = FakeClock()
    cached = CachingGeoIPProvider(inner, ttl_seconds=100, time_source=clock.now)

    first = cached.lookup("8.8.8.8")
    second = cached.lookup("8.8.8.8")

    assert first == second
    assert len(http.calls) == 1


def test_cache_expires_after_its_ttl():
    inner, http = make_provider(
        [[ip_api_entry("8.8.8.8", 37.0, -122.0)], [ip_api_entry("8.8.8.8", 37.0, -122.0)]]
    )
    clock = FakeClock()
    cached = CachingGeoIPProvider(inner, ttl_seconds=100, time_source=clock.now)

    cached.lookup("8.8.8.8")
    clock.advance(101)
    cached.lookup("8.8.8.8")

    assert len(http.calls) == 2


def test_cache_only_fetches_the_misses_in_a_mixed_batch():
    inner, http = make_provider(
        [
            [ip_api_entry("8.8.8.8", 37.0, -122.0)],
            [ip_api_entry("1.1.1.1", 51.0, 0.0)],
        ]
    )
    cached = CachingGeoIPProvider(inner, ttl_seconds=1000)

    cached.lookup("8.8.8.8")
    results = cached.lookup_many(["8.8.8.8", "1.1.1.1"])

    assert http.calls[1][2] == [{"query": "1.1.1.1", "fields": IpApiProvider._FIELDS}]
    assert results["8.8.8.8"] is not None and results["1.1.1.1"] is not None


def test_cache_evicts_when_full():
    inner = NullGeoIPProvider()
    cached = CachingGeoIPProvider(inner, max_entries=2)
    cached.lookup_many(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    assert len(cached._entries) <= 2


def test_null_provider_locates_nothing():
    provider = NullGeoIPProvider()
    assert provider.lookup("8.8.8.8") is None
    assert provider.lookup_many(["8.8.8.8"]) == {"8.8.8.8": None}


# ------------------------------------------------------------------ distance


def test_haversine_matches_a_known_distance():
    london = (51.5074, -0.1278)
    paris = (48.8566, 2.3522)
    assert haversine_km(london, paris) == pytest.approx(343.0, abs=2.0)


def test_haversine_is_zero_for_the_same_point():
    assert haversine_km((10.0, 20.0), (10.0, 20.0)) == pytest.approx(0.0)


def test_haversine_handles_antipodes():
    assert haversine_km((0.0, 0.0), (0.0, 180.0)) == pytest.approx(20015.0, abs=5.0)
