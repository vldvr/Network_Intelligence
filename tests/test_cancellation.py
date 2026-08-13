"""Cancellation token semantics, including under concurrency."""

from __future__ import annotations

import threading
import time

import pytest

from netintel.cancellation import CancellationToken
from netintel.errors import CancelledError


def test_a_new_token_is_not_cancelled():
    token = CancellationToken()
    assert token.cancelled is False
    assert token.should_continue() is True
    token.raise_if_cancelled()


def test_cancel_is_observable_and_idempotent():
    token = CancellationToken()
    token.cancel()
    token.cancel()
    assert token.cancelled is True
    assert token.should_continue() is False
    with pytest.raises(CancelledError):
        token.raise_if_cancelled()


def test_reset_allows_reuse_for_a_new_run():
    token = CancellationToken()
    token.cancel()
    token.reset()
    assert token.cancelled is False


def test_wait_returns_immediately_once_cancelled():
    token = CancellationToken()
    token.cancel()
    started = time.monotonic()
    assert token.wait(5.0) is True
    assert time.monotonic() - started < 0.5


def test_wait_times_out_when_not_cancelled():
    assert CancellationToken().wait(0.01) is False


def test_cancel_from_another_thread_wakes_a_waiter():
    """This is the behaviour a Stop button depends on."""
    token = CancellationToken()
    threading.Timer(0.05, token.cancel).start()

    started = time.monotonic()
    assert token.wait(5.0) is True
    assert time.monotonic() - started < 1.0


def test_context_manager_cancels_on_exit():
    with CancellationToken() as token:
        assert token.cancelled is False
    assert token.cancelled is True
