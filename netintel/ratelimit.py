"""Token-bucket rate limiting.

ip-api.com allows 45 requests per minute from an address and blackholes the
caller for an hour after that. The original code approximated compliance with
``time.sleep(1.5)`` after every lookup, which both over-waits on small scans
and still exceeds the quota once anything else in the process shares the
budget. A shared bucket is the correct primitive: it permits bursts up to the
quota and only blocks when the budget is genuinely spent.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from netintel.cancellation import NEVER_CANCELLED, CancellationToken


class SystemClock:
    """Default :class:`netintel.ports.Clock` backed by the monotonic clock."""

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True, slots=True)
class Quota:
    """``requests`` calls allowed per ``per_seconds`` window."""

    requests: int
    per_seconds: float

    @property
    def refill_per_second(self) -> float:
        return self.requests / self.per_seconds


class TokenBucket:
    """Thread-safe token bucket.

    Safe to share between the GUI worker and the CLI in the same process;
    every caller draws from the same budget.
    """

    def __init__(self, quota: Quota, *, clock: SystemClock | None = None) -> None:
        if quota.requests <= 0 or quota.per_seconds <= 0:
            raise ValueError("quota must be positive")
        self._quota = quota
        self._clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._tokens = float(quota.requests)
        self._updated = self._clock.now()

    @property
    def available(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens

    def _refill(self) -> None:
        now = self._clock.now()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(
            float(self._quota.requests),
            self._tokens + elapsed * self._quota.refill_per_second,
        )

    def _take(self, cost: float) -> float:
        """Consume ``cost`` tokens, returning the seconds to wait first."""
        with self._lock:
            self._refill()
            if self._tokens >= cost:
                self._tokens -= cost
                return 0.0
            deficit = cost - self._tokens
            self._tokens -= cost  # go negative; the wait pays the debt back
            return deficit / self._quota.refill_per_second

    def acquire(self, cost: float = 1.0, *, token: CancellationToken = NEVER_CANCELLED) -> bool:
        """Block until ``cost`` tokens are available.

        Returns ``False`` if cancellation interrupted the wait, so callers can
        abandon the work instead of proceeding with a budget they never got.
        """
        delay = self._take(cost)
        if delay <= 0:
            return not token.cancelled
        return not token.wait(delay)
