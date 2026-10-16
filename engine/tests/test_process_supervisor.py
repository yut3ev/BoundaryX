import sys
import threading
import time

import pytest

from boundaryx.jobs.process_supervisor import (
    ProcessSupervisor,
    ProcessTimeoutError,
)


def test_supervisor_runs_command():
    supervisor = ProcessSupervisor()
    code, out, err = supervisor.run_command([sys.executable, "-c", "print('hello from python')"])
    assert code == 0
    assert "hello from python" in out


def test_supervisor_sanitizes_environment():
    supervisor = ProcessSupervisor()
    code, out, err = supervisor.run_command(
        [sys.executable, "-c", "import os; print('GEMINI_API_KEY' in os.environ)"]
    )
    assert code == 0
    assert "False" in out


def test_supervisor_timeout():
    supervisor = ProcessSupervisor()
    with pytest.raises(ProcessTimeoutError):
        supervisor.run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout_seconds=1)


def test_supervisor_cancellation():
    supervisor = ProcessSupervisor()
    cancel_event = threading.Event()

    def cancel_after_delay():
        time.sleep(0.5)
        cancel_event.set()

    threading.Thread(target=cancel_after_delay).start()
    code, out, err = supervisor.run_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_seconds=20,
        cancel_event=cancel_event,
    )
    assert code == -1
    assert "cancelled" in err.lower()
