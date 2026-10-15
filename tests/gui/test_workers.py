"""Unit tests for background workers and asynchronous task execution."""

from __future__ import annotations

import time
from typing import Any

import pytest
from PySide6.QtCore import QCoreApplication, QThreadPool

from boundaryx.workers import (
    GenericWorker,
    ThreadedTask,
    WorkerSignals,
    run_in_background,
)


@pytest.fixture(scope="session")
def qapp() -> QCoreApplication:
    """Fixture providing QCoreApplication for Qt signal processing."""
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])
    return app


def test_worker_signals_creation(qapp: QCoreApplication) -> None:
    """Verify WorkerSignals has all required Qt signals."""
    signals = WorkerSignals()
    assert hasattr(signals, "started")
    assert hasattr(signals, "progress")
    assert hasattr(signals, "result")
    assert hasattr(signals, "error")
    assert hasattr(signals, "finished")
    assert hasattr(signals, "aborted")


def test_generic_worker_success(qapp: QCoreApplication) -> None:
    """Verify GenericWorker executes callable and dispatches results."""

    def compute(a: int, b: int) -> int:
        return a * b

    worker = GenericWorker(compute, 6, 7)
    events: list[str] = []
    results: list[Any] = []

    worker.signals.started.connect(lambda: events.append("started"))
    worker.signals.result.connect(lambda res: results.append(res))
    worker.signals.finished.connect(lambda: events.append("finished"))

    worker.run()

    assert events == ["started", "finished"]
    assert results == [42]
    assert not worker.is_aborted


def test_generic_worker_progress(qapp: QCoreApplication) -> None:
    """Verify GenericWorker supports progress_callback injection."""

    def task_with_progress(steps: int, progress_callback: Any = None) -> str:
        for i in range(steps):
            if progress_callback:
                progress_callback(int((i + 1) / steps * 100), f"Step {i + 1}")
        return "done"

    worker = GenericWorker(task_with_progress, 3)
    progress_updates: list[tuple[int, str]] = []
    worker.signals.progress.connect(lambda pct, msg: progress_updates.append((pct, msg)))

    worker.run()

    assert len(progress_updates) == 3
    assert progress_updates[0] == (33, "Step 1")
    assert progress_updates[2] == (100, "Step 3")


def test_generic_worker_error_safety(qapp: QCoreApplication) -> None:
    """Ensure exceptions inside GenericWorker are caught and safely signaled."""

    def failing_task() -> None:
        raise ValueError("Simulated network timeout")

    worker = GenericWorker(failing_task)
    errors: list[tuple[str, str]] = []
    finished_called = False

    worker.signals.error.connect(lambda title, details: errors.append((title, details)))
    worker.signals.finished.connect(lambda: nonlocal_set())

    def nonlocal_set() -> None:
        nonlocal finished_called
        finished_called = True

    # Should not raise exception
    worker.run()

    assert len(errors) == 1
    err_title, err_details = errors[0]
    assert "ValueError" in err_title
    assert "Simulated network timeout" in err_title
    assert "Traceback" in err_details
    assert finished_called is True


def test_generic_worker_abort(qapp: QCoreApplication) -> None:
    """Verify worker cancellation via abort()."""

    def long_task(is_aborted: Any = None) -> str:
        if is_aborted and is_aborted():
            return "aborted"
        return "completed"

    worker = GenericWorker(long_task)
    aborted_events: list[bool] = []
    worker.signals.aborted.connect(lambda: aborted_events.append(True))

    worker.abort()
    assert worker.is_aborted is True

    worker.run()
    assert aborted_events == [True]


def test_threaded_task_execution(qapp: QCoreApplication) -> None:
    """Verify ThreadedTask executes in a dedicated QThread."""

    def background_calculation(val: int) -> int:
        return val**2

    task = ThreadedTask(background_calculation, 8)
    results: list[int] = []
    task.signals.result.connect(lambda res: results.append(res))

    task.start()
    task.wait(3000)
    qapp.processEvents()

    assert results == [64]
    assert not task.isRunning()


def test_threaded_task_cancellation(qapp: QCoreApplication) -> None:
    """Verify ThreadedTask graceful abort and cancel_and_wait."""

    def long_running(is_aborted: Any = None) -> None:
        while not (is_aborted and is_aborted()):
            time.sleep(0.01)

    task = ThreadedTask(long_running)
    task.start()

    time.sleep(0.05)
    assert task.isRunning()

    terminated = task.cancel_and_wait(timeout_ms=2000)
    qapp.processEvents()
    assert terminated is True
    assert task.is_aborted is True
    assert not task.isRunning()


def test_run_in_background_pool(qapp: QCoreApplication) -> None:
    """Verify run_in_background submits to QThreadPool."""
    pool = QThreadPool()
    results: list[str] = []

    def quick_job() -> str:
        return "job_ok"

    worker = run_in_background(quick_job, thread_pool=pool)
    worker.signals.result.connect(lambda res: results.append(res))

    pool.waitForDone(3000)
    qapp.processEvents()
    assert results == ["job_ok"]
