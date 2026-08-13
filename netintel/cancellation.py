"""Cooperative cancellation.

The original code used a bare ``self.scanning`` boolean owned by a widget and
read from a worker thread. That has two problems: the flag was flipped to
"stopped" in the UI before the worker had actually finished (so a restart could
run two workers at once), and every operation had to re-invent the check.

A token makes the contract explicit — one object passed down the call stack,
checked at every interruptible point, with a ``wait`` that returns early on
cancellation instead of sleeping through it.
"""

from __future__ import annotations

import threading
from types import TracebackType

from netintel.errors import CancelledError


class CancellationToken:
    """A thread-safe, one-shot cancellation signal."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        """Request cancellation. Idempotent and safe from any thread."""
        self._event.set()

    def reset(self) -> None:
        """Return the token to its un-cancelled state for a new run."""
        self._event.clear()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise CancelledError("operation cancelled")

    def should_continue(self) -> bool:
        """Predicate form, for passing to backends as a plain callable."""
        return not self._event.is_set()

    def wait(self, seconds: float) -> bool:
        """Sleep up to ``seconds``, returning ``True`` if cancelled meanwhile.

        This is the only sleep primitive ``core`` uses. ``time.sleep`` in a
        worker means a stop button that appears frozen for the length of the
        nap; waiting on the event makes cancellation feel immediate.
        """
        return self._event.wait(seconds)

    def __enter__(self) -> CancellationToken:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.cancel()


NEVER_CANCELLED = CancellationToken()
"""A token that is never tripped — a convenient default for one-shot calls."""
