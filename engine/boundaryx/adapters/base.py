from abc import ABC, abstractmethod
import shutil
from typing import Any, Dict, List, Optional, Tuple

from boundaryx.jobs.process_supervisor import ProcessSupervisor


class ToolAdapter(ABC):
    """
    Abstract contract for external recon/security tool adapters.
    Guarantees consistent discovery, version checks, and output parsing.
    """

    def __init__(self, executable_name: str, custom_path: Optional[str] = None):
        self.executable_name = executable_name
        self.custom_path = custom_path
        self.supervisor = ProcessSupervisor()

    def get_binary_path(self) -> Optional[str]:
        if self.custom_path:
            return self.custom_path
        return shutil.which(self.executable_name)

    def detect(self) -> bool:
        """Returns True if the tool executable is found on PATH or custom path."""
        return self.get_binary_path() is not None

    @abstractmethod
    def version(self) -> str:
        """Returns detected version string or 'unknown'."""
        pass

    @abstractmethod
    def capabilities(self) -> Dict[str, Any]:
        """Returns dictionary of operations, formats, and impact (passive/active)."""
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> None:
        """Validates configuration parameters and limits."""
        pass

    @abstractmethod
    def build_argv(self, targets: List[str], config: Dict[str, Any]) -> List[str]:
        """Constructs safe argv array, strictly avoiding shell strings."""
        pass

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parses stdout/stderr into typed normalized asset or finding dictionaries."""
        pass

    def health_check(self) -> Tuple[bool, str]:
        """Performs a safe, non-target health check (e.g. running --version)."""
        if not self.detect():
            return False, f"Executable '{self.executable_name}' is not installed"
        try:
            ver = self.version()
            return True, f"Healthy (version: {ver})"
        except Exception as e:
            return False, f"Health check failed: {str(e)}"
