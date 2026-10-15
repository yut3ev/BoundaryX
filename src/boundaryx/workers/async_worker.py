"""Background asynchronous worker execution for PySide6 using QThread, QRunnable, and Signals.

Safely executes long-running callables (HTTP requests, HAR imports, batch tests,
evidence collection, graph generation) without freezing the GUI event loop.
"""

from __future__ import annotations

import inspect
import logging
import threading
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThread, QThreadPool, Signal

logger = logging.getLogger(__name__)


class WorkerSignals(QObject):
    """Signals emitted by background worker tasks to the Qt GUI thread."""

    started = Signal()
    progress = Signal(int, str)  # percent (0-100), status message
    result = Signal(object)  # task execution return value
    error = Signal(str, str)  # error title/type, detailed traceback string
    finished = Signal()  # always emitted upon task completion (success, error, or aborted)
    aborted = Signal()  # emitted if task was explicitly aborted


class GenericWorker(QRunnable):
    """QRunnable worker for executing arbitrary callables via QThreadPool.

    Provides cancellation detection, exception safety, and Qt signal forwarding.
    """

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        """Initialize the runnable worker.

        Args:
            fn: Callable to execute in the background thread.
            *args: Positional arguments for fn.
            **kwargs: Keyword arguments for fn.
        """
        super().__init__()
        self.signals = WorkerSignals()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._abort_event = threading.Event()
        self.setAutoDelete(True)

    def abort(self) -> None:
        """Request task cancellation."""
        self._abort_event.set()

    @property
    def is_aborted(self) -> bool:
        """Check if task cancellation was requested."""
        return self._abort_event.is_set()

    def _emit_progress(self, percent: int, message: str = "") -> None:
        """Progress callback invoked by long-running tasks."""
        if not self.is_aborted:
            self.signals.progress.emit(percent, message)

    def run(self) -> None:
        """Run the callable with error handling and signal dispatching."""
        self.signals.started.emit()

        if self.is_aborted:
            self.signals.aborted.emit()
            self.signals.finished.emit()
            return

        try:
            # Check if callable accepts progress callback or cancellation token
            call_kwargs = dict(self._kwargs)
            try:
                sig = inspect.signature(self._fn)
                if "progress_callback" in sig.parameters and "progress_callback" not in call_kwargs:
                    call_kwargs["progress_callback"] = self._emit_progress
                if "is_aborted" in sig.parameters and "is_aborted" not in call_kwargs:
                    call_kwargs["is_aborted"] = lambda: self.is_aborted
            except (ValueError, TypeError):
                # Built-ins or C-extensions might not support signature inspection
                pass

            result = self._fn(*self._args, **call_kwargs)

            if self.is_aborted:
                self.signals.aborted.emit()
            else:
                self.signals.result.emit(result)

        except Exception as exc:
            err_title = f"{type(exc).__name__}: {exc}"
            err_details = traceback.format_exc()
            logger.error("Error in background worker task: %s\n%s", err_title, err_details)
            self.signals.error.emit(err_title, err_details)

        finally:
            self.signals.finished.emit()


class ThreadedTask(QThread):
    """Dedicated QThread worker for continuous or complex long-running operations.

    Inherits QThread and provides safe aborting and lifecycle management.
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        *args: Any,
        parent: QObject | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the threaded task.

        Args:
            fn: Callable to execute inside the thread.
            *args: Positional arguments for fn.
            parent: Optional Qt parent object.
            **kwargs: Keyword arguments for fn.
        """
        super().__init__(parent)
        self.signals = WorkerSignals()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._abort_event = threading.Event()

    def abort(self) -> None:
        """Signal the task to abort gracefully."""
        self._abort_event.set()

    @property
    def is_aborted(self) -> bool:
        """Check whether abort was requested."""
        return self._abort_event.is_set()

    def cancel_and_wait(self, timeout_ms: int = 3000) -> bool:
        """Abort and wait for the thread to terminate.

        Args:
            timeout_ms: Maximum time to wait in milliseconds.

        Returns:
            True if thread terminated within timeout, False otherwise.
        """
        self.abort()
        if self.isRunning():
            return self.wait(timeout_ms)
        return True

    def _emit_progress(self, percent: int, message: str = "") -> None:
        """Progress callback invoked from within worker thread."""
        if not self.is_aborted:
            self.signals.progress.emit(percent, message)

    def run(self) -> None:
        """Execute the task safely inside the dedicated thread."""
        self.signals.started.emit()

        if self.is_aborted:
            self.signals.aborted.emit()
            self.signals.finished.emit()
            return

        try:
            call_kwargs = dict(self._kwargs)
            try:
                sig = inspect.signature(self._fn)
                if "progress_callback" in sig.parameters and "progress_callback" not in call_kwargs:
                    call_kwargs["progress_callback"] = self._emit_progress
                if "is_aborted" in sig.parameters and "is_aborted" not in call_kwargs:
                    call_kwargs["is_aborted"] = lambda: self.is_aborted
            except (ValueError, TypeError):
                pass

            result = self._fn(*self._args, **call_kwargs)

            if self.is_aborted:
                self.signals.aborted.emit()
            else:
                self.signals.result.emit(result)

        except Exception as exc:
            err_title = f"{type(exc).__name__}: {exc}"
            err_details = traceback.format_exc()
            logger.error("Error in ThreadedTask: %s\n%s", err_title, err_details)
            self.signals.error.emit(err_title, err_details)

        finally:
            self.signals.finished.emit()


# Global tracker to keep Python references alive during QRunnable execution
_active_workers: set[GenericWorker] = set()
_active_workers_lock = threading.Lock()


def run_in_background(
    fn: Callable[..., Any],
    *args: Any,
    thread_pool: QThreadPool | None = None,
    **kwargs: Any,
) -> GenericWorker:
    """Submit a callable to the QThreadPool and safely track its lifecycle.

    Args:
        fn: Callable function or method.
        *args: Positional arguments.
        thread_pool: Optional QThreadPool instance (defaults to QThreadPool.globalInstance()).
        **kwargs: Keyword arguments.

    Returns:
        The instantiated GenericWorker with its signals accessible.
    """
    worker = GenericWorker(fn, *args, **kwargs)
    pool = thread_pool or QThreadPool.globalInstance()

    with _active_workers_lock:
        _active_workers.add(worker)

    def _cleanup() -> None:
        with _active_workers_lock:
            _active_workers.discard(worker)

    worker.signals.finished.connect(_cleanup)
    pool.start(worker)
    return worker


def get_active_worker_count() -> int:
    """Return the number of background workers currently executing."""
    with _active_workers_lock:
        return len(_active_workers)


def cancel_all_workers() -> None:
    """Signal all active background workers to abort."""
    with _active_workers_lock:
        for worker in list(_active_workers):
            worker.abort()
