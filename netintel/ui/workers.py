"""Background execution for the GUI.

This module exists because of the single most serious defect in the original
code: worker threads called ``self.output_display.append(...)`` and
``setEnabled(...)`` directly. Qt widgets may only be touched from the thread
that owns them. Doing otherwise is undefined behaviour — in practice a
corrupted document model, a hang, or a segfault, none of which reproduce
reliably enough to be reported as a bug.

The rule enforced here: **work happens in a worker, results arrive as
signals**. A worker never holds a reference to a widget. Progress is emitted,
never rendered.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PyQt5.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot

from netintel.cancellation import CancellationToken
from netintel.errors import CancelledError, NetIntelError


class WorkerSignals(QObject):
    """The only channel between a worker and the UI thread.

    Signals are the crossing point: Qt queues them and delivers on the
    receiving object's thread, so slots run on the UI thread by construction.
    """

    started = pyqtSignal()
    progress = pyqtSignal(object)
    """Emitted with a domain model — never with pre-formatted text.

    Formatting is a view concern; sending a string would mean the worker has
    already decided how the result looks."""

    finished = pyqtSignal(object)
    failed = pyqtSignal(str)
    done = pyqtSignal()
    """Always emitted last, whatever the outcome. Cleanup lives here so the
    UI cannot be left with a disabled Start button after a failure — the bug
    the original hit whenever a scan raised before its reset code."""


class Worker(QRunnable):
    """Runs one callable on the thread pool with a cancellation token.

    The callable receives the token as a keyword argument and may report
    intermediate results through ``on_progress``.
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        *args: Any,
        token: CancellationToken | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.token = token or CancellationToken()
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self) -> None:
        self.signals.started.emit()
        try:
            result = self._fn(
                *self._args,
                token=self.token,
                on_progress=self.signals.progress.emit,
                **self._kwargs,
            )
        except CancelledError:
            self.signals.finished.emit(None)
        except NetIntelError as exc:
            # Domain errors carry a message meant for a person.
            self.signals.failed.emit(str(exc))
        except Exception as exc:  # unexpected: show the type, keep the app alive
            self.signals.failed.emit(f"unexpected {type(exc).__name__}: {exc}")
        else:
            self.signals.finished.emit(result)
        finally:
            self.signals.done.emit()

    def cancel(self) -> None:
        self.token.cancel()


class WorkerHost:
    """Owns at most one in-flight worker for a panel.

    Serialising work per panel removes a race the original had: ``stop`` flipped
    the flag and re-enabled Start immediately, so a second run could begin
    while the first thread was still writing results into the same widget.
    Here a new run is refused until the previous worker signals ``done``.
    """

    def __init__(self, pool: QThreadPool | None = None) -> None:
        self._pool = pool or QThreadPool.globalInstance()
        self._current: Worker | None = None

    @property
    def busy(self) -> bool:
        return self._current is not None

    def start(self, worker: Worker) -> bool:
        """Queue ``worker``; returns ``False`` if one is already running."""
        if self._current is not None:
            return False
        self._current = worker
        worker.signals.done.connect(self._clear)
        self._pool.start(worker)
        return True

    def cancel(self) -> None:
        if self._current is not None:
            self._current.cancel()

    def _clear(self) -> None:
        self._current = None

    def wait_for_done(self, timeout_ms: int = 5000) -> bool:
        """Block until queued work finishes — used on window close.

        Letting the process exit while a worker still holds a raw socket is
        how you get a Qt teardown crash on the way out.
        """
        return bool(self._pool.waitForDone(timeout_ms))
