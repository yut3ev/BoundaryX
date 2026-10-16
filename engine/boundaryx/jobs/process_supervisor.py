import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("boundaryx.jobs.supervisor")

MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB output cap


class ProcessExecutionError(Exception):
    pass


class ProcessTimeoutError(ProcessExecutionError):
    pass


class ProcessSupervisor:
    """
    Subprocess execution manager.
    - Always executes via argv array, NEVER shell=True.
    - Uses process groups for clean termination of entire child process trees.
    - Enforces timeout and output size limits.
    - Strips sensitive tokens from process environment.
    """

    @staticmethod
    def get_sanitized_env() -> Dict[str, str]:
        """Returns minimal, sanitized environment variables."""
        env = os.environ.copy()
        # Strip common sensitive credentials from child process env
        sensitive_vars = [
            "GEMINI_API_KEY",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "TOKEN",
            "SECRET",
            "PASSWORD",
        ]
        for var in sensitive_vars:
            env.pop(var, None)
        return env

    def run_command(
        self,
        argv: List[str],
        cwd: Optional[Path] = None,
        timeout_seconds: int = 300,
        cancel_event: Optional[threading.Event] = None,
    ) -> Tuple[int, str, str]:
        """
        Runs a subprocess synchronously with safety limits and cancellation monitoring.
        Returns: (exit_code, stdout_str, stderr_str)
        """
        if not argv or not argv[0]:
            raise ProcessExecutionError("Argv array cannot be empty")

        clean_env = self.get_sanitized_env()
        creationflags = 0
        preexec_fn = None

        if sys.platform == "win32":
            # Create a new process group so we can terminate child trees
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            preexec_fn = os.setsid

        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd) if cwd else None,
                env=clean_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
                preexec_fn=preexec_fn,
            )
        except FileNotFoundError as e:
            raise ProcessExecutionError(f"Executable not found: {argv[0]}") from e
        except Exception as e:
            raise ProcessExecutionError(f"Failed to spawn process {argv[0]}: {str(e)}") from e

        start_time = time.time()

        def kill_process_tree():
            try:
                if sys.platform == "win32":
                    subprocess.call(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                else:
                    os.killpg(os.getpgid(proc.pid), 9)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        while proc.poll() is None:
            # Check cancellation token
            if cancel_event and cancel_event.is_set():
                logger.info("Cancellation requested, terminating process %d...", proc.pid)
                kill_process_tree()
                return -1, "", "Process cancelled by user"

            # Check timeout
            if time.time() - start_time > timeout_seconds:
                logger.warning("Process %d timed out after %d seconds", proc.pid, timeout_seconds)
                kill_process_tree()
                raise ProcessTimeoutError(f"Process timed out after {timeout_seconds} seconds")

            time.sleep(0.1)

        # Read remaining output
        out, err = proc.communicate()
        if len(out.encode("utf-8")) > MAX_OUTPUT_BYTES:
            out = out[: MAX_OUTPUT_BYTES] + "\n[OUTPUT_TRUNCATED_MAX_BYTES_EXCEEDED]"
        if len(err.encode("utf-8")) > MAX_OUTPUT_BYTES:
            err = err[: MAX_OUTPUT_BYTES] + "\n[OUTPUT_TRUNCATED_MAX_BYTES_EXCEEDED]"

        return proc.returncode, out, err
