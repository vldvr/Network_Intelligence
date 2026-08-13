"""HTTP transport backed by ``requests``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from netintel.errors import BackendUnavailableError, GeoIPError

_USER_AGENT = "NetworkIntelligence/1.0 (+https://github.com/vldvr/network_intelligence)"


class RequestsHttpClient:
    """A small, retrying JSON client.

    Retries only idempotent failures (connection errors, 429, 5xx) and backs
    off between attempts. It does not retry a 4xx: repeating a request the
    server has already rejected is how a client earns a longer ban.
    """

    def __init__(
        self,
        *,
        retries: int = 2,
        backoff_s: float = 0.5,
        session: Any | None = None,
    ) -> None:
        self._retries = max(0, retries)
        self._backoff = backoff_s
        self._session = session if session is not None else self._new_session()

    @staticmethod
    def _new_session() -> Any:
        try:
            import requests
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise BackendUnavailableError(
                "requests", "install it with `pip install requests`"
            ) from exc

        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT, "Accept": "application/json"})
        return session

    def get_json(
        self, url: str, *, params: Mapping[str, str] | None = None, timeout: float = 5.0
    ) -> Any:
        return self._request("GET", url, params=params, timeout=timeout)

    def post_json(self, url: str, *, payload: Any, timeout: float = 5.0) -> Any:
        return self._request("POST", url, json=payload, timeout=timeout)

    def _request(self, method: str, url: str, *, timeout: float, **kwargs: Any) -> Any:
        import time

        import requests

        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                response = self._session.request(method, url, timeout=timeout, **kwargs)
            except requests.RequestException as exc:
                last_error = exc
            else:
                if response.status_code == 429 or response.status_code >= 500:
                    last_error = GeoIPError(f"provider returned HTTP {response.status_code}")
                elif response.status_code >= 400:
                    raise GeoIPError(f"provider returned HTTP {response.status_code}")
                else:
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise GeoIPError("provider returned malformed JSON") from exc

            if attempt < self._retries:
                time.sleep(self._backoff * (2**attempt))

        raise GeoIPError(f"request to {url} failed: {last_error}")
