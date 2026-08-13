"""Token bucket, on a virtual clock."""

from __future__ import annotations

import pytest

from netintel.cancellation import CancellationToken
from netintel.ratelimit import Quota, TokenBucket
from tests.conftest import FakeClock


def test_a_full_bucket_permits_a_burst():
    bucket = TokenBucket(Quota(5, 60.0), clock=FakeClock())
    for _ in range(5):
        assert bucket.acquire() is True
    assert bucket.available == pytest.approx(0.0)


def test_exhausted_bucket_waits_for_a_refill():
    token = CancellationToken()
    bucket = TokenBucket(Quota(2, 10.0), clock=FakeClock())
    bucket.acquire()
    bucket.acquire()

    # The sixth call must wait; cancelling the token proves the wait happened
    # rather than the call sailing through.
    token.cancel()
    assert bucket.acquire(token=token) is False


def test_tokens_refill_over_time():
    clock = FakeClock()
    bucket = TokenBucket(Quota(60, 60.0), clock=clock)
    for _ in range(60):
        bucket.acquire()

    clock.advance(30)
    assert bucket.available == pytest.approx(30.0, abs=0.01)


def test_refill_is_capped_at_the_quota():
    clock = FakeClock()
    bucket = TokenBucket(Quota(10, 60.0), clock=clock)
    clock.advance(10_000)
    assert bucket.available == pytest.approx(10.0)


def test_cancelled_token_short_circuits_an_available_acquire():
    token = CancellationToken()
    token.cancel()
    bucket = TokenBucket(Quota(10, 60.0), clock=FakeClock())
    assert bucket.acquire(token=token) is False


@pytest.mark.parametrize("quota", [Quota(0, 60.0), Quota(10, 0.0), Quota(-1, 60.0)])
def test_invalid_quota_is_rejected(quota):
    with pytest.raises(ValueError):
        TokenBucket(quota)
