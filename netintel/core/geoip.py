"""IP geolocation.

Three things changed from the original single-IP ``requests.get`` per host:

1. **Batching.** ip-api exposes a batch endpoint taking 100 addresses per
   call. Geolocating a /24 went from 254 requests and ~6 minutes of
   ``time.sleep`` to 3 requests.
2. **Caching.** Consecutive hops of a trace routinely share an address, and a
   rescan repeats the same set. Results are stable for hours; re-asking is
   pure waste of a 45/minute budget.
3. **A provider seam.** :class:`GeoIPProvider` is a protocol, so a paid
   provider, a local MaxMind database or a fake in tests all drop in without
   the callers knowing.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from netintel.cancellation import NEVER_CANCELLED, CancellationToken
from netintel.core.targets import is_public
from netintel.errors import GeoIPError
from netintel.models import GeoLocation
from netintel.ports import HttpClient
from netintel.ratelimit import Quota, TokenBucket

IP_API_QUOTA = Quota(requests=40, per_seconds=60.0)
"""Deliberately below ip-api's documented 45/min so a shared process stays clear
of the ban threshold."""

BATCH_LIMIT = 100
CACHE_TTL_SECONDS = 6 * 60 * 60


@runtime_checkable
class GeoIPProvider(Protocol):
    """Resolves IP addresses to approximate locations."""

    @property
    def name(self) -> str: ...

    def lookup(self, ip: str) -> GeoLocation | None: ...

    def lookup_many(
        self, ips: Sequence[str], *, token: CancellationToken = NEVER_CANCELLED
    ) -> dict[str, GeoLocation | None]: ...


def _is_locatable(ip: str) -> bool:
    """Private, loopback and reserved space has no meaningful geolocation.

    Asking anyway burns quota and, for the original scanner, printed a line of
    apology per host on every LAN scan.
    """
    try:
        return is_public(ipaddress.ip_address(ip))
    except ValueError:
        return False


class NullGeoIPProvider:
    """Provider that resolves nothing — used when running offline."""

    name = "disabled"

    def lookup(self, ip: str) -> GeoLocation | None:
        return None

    def lookup_many(
        self, ips: Sequence[str], *, token: CancellationToken = NEVER_CANCELLED
    ) -> dict[str, GeoLocation | None]:
        return {ip: None for ip in ips}


class IpApiProvider:
    """ip-api.com backend (free tier).

    The free tier is HTTP-only and unauthenticated, so responses are treated
    as untrusted input: fields are read defensively and only the ones this
    application understands are kept. Nothing from the response is
    interpolated into a shell command, a path or a query.
    """

    name = "ip-api.com"

    _FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,as,proxy,hosting,query"

    def __init__(
        self,
        http: HttpClient,
        *,
        bucket: TokenBucket | None = None,
        base_url: str = "http://ip-api.com",
        timeout: float = 5.0,
    ) -> None:
        self._http = http
        self._bucket = bucket or TokenBucket(IP_API_QUOTA)
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def lookup(self, ip: str) -> GeoLocation | None:
        return self.lookup_many([ip])[ip]

    def lookup_many(
        self, ips: Sequence[str], *, token: CancellationToken = NEVER_CANCELLED
    ) -> dict[str, GeoLocation | None]:
        results: dict[str, GeoLocation | None] = {ip: None for ip in ips}
        pending = [ip for ip in dict.fromkeys(ips) if _is_locatable(ip)]

        for chunk in _chunked(pending, BATCH_LIMIT):
            if token.cancelled:
                break
            # One batch call costs one request against the quota.
            if not self._bucket.acquire(token=token):
                break
            for location in self._fetch_batch(chunk):
                results[location.ip] = location
        return results

    def _fetch_batch(self, ips: Sequence[str]) -> list[GeoLocation]:
        payload = [{"query": ip, "fields": self._FIELDS} for ip in ips]
        try:
            data = self._http.post_json(
                f"{self._base_url}/batch", payload=payload, timeout=self._timeout
            )
        except Exception as exc:  # transport-specific; normalise for callers
            raise GeoIPError(f"geolocation request failed: {exc}") from exc

        if not isinstance(data, list):
            raise GeoIPError("geolocation provider returned an unexpected payload")

        locations: list[GeoLocation] = []
        for entry in data:
            location = self._parse_entry(entry)
            if location is not None:
                locations.append(location)
        return locations

    def _parse_entry(self, entry: Any) -> GeoLocation | None:
        if not isinstance(entry, Mapping):
            return None
        if entry.get("status") != "success":
            return None
        query = entry.get("query")
        lat, lon = entry.get("lat"), entry.get("lon")
        if not isinstance(query, str):
            return None
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            return None
        return GeoLocation(
            ip=query,
            latitude=float(lat),
            longitude=float(lon),
            city=_opt_str(entry.get("city")),
            region=_opt_str(entry.get("regionName")),
            country=_opt_str(entry.get("country")),
            country_code=_opt_str(entry.get("countryCode")),
            autonomous_system=_opt_str(entry.get("as")),
            is_proxy=bool(entry.get("proxy", False)),
            is_hosting=bool(entry.get("hosting", False)),
            source=self.name,
        )


def _opt_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


@dataclass(slots=True)
class _CacheEntry:
    location: GeoLocation | None
    expires_at: float


class CachingGeoIPProvider:
    """TTL cache in front of another provider.

    A decorator rather than a flag on the provider: caching is a policy, and
    the thing that knows how long an answer stays true is not the thing that
    knows how to fetch it.
    """

    def __init__(
        self,
        inner: GeoIPProvider,
        *,
        ttl_seconds: float = CACHE_TTL_SECONDS,
        max_entries: int = 8192,
        time_source: Any = time.monotonic,
    ) -> None:
        self._inner = inner
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._now = time_source
        self._lock = threading.Lock()
        self._entries: dict[str, _CacheEntry] = {}

    @property
    def name(self) -> str:
        return f"{self._inner.name} (cached)"

    def lookup(self, ip: str) -> GeoLocation | None:
        return self.lookup_many([ip])[ip]

    def lookup_many(
        self, ips: Sequence[str], *, token: CancellationToken = NEVER_CANCELLED
    ) -> dict[str, GeoLocation | None]:
        now = self._now()
        results: dict[str, GeoLocation | None] = {}
        misses: list[str] = []

        with self._lock:
            for ip in ips:
                entry = self._entries.get(ip)
                if entry is not None and entry.expires_at > now:
                    results[ip] = entry.location
                else:
                    misses.append(ip)

        if misses:
            fetched = self._inner.lookup_many(misses, token=token)
            expiry = self._now() + self._ttl
            with self._lock:
                for ip, location in fetched.items():
                    self._store(ip, location, expiry)
            results.update(fetched)

        return {ip: results.get(ip) for ip in ips}

    def _store(self, ip: str, location: GeoLocation | None, expiry: float) -> None:
        if len(self._entries) >= self._max_entries:
            # Cheap eviction: drop the oldest insertion. dicts preserve order.
            oldest = next(iter(self._entries))
            self._entries.pop(oldest, None)
        self._entries[ip] = _CacheEntry(location=location, expires_at=expiry)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def _chunked(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in kilometres between two (lat, lon) pairs.

    Implemented here rather than pulling in geopy: the original dependency
    existed solely for this one call, and a transitive dependency on a
    geocoding client is a poor trade for eight lines of trigonometry.
    """
    from math import asin, cos, radians, sin, sqrt

    earth_radius_km = 6371.0088
    lat1, lon1 = radians(a[0]), radians(a[1])
    lat2, lon2 = radians(b[0]), radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return 2 * earth_radius_km * asin(sqrt(min(1.0, h)))
