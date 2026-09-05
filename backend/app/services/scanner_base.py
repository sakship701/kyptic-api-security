from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict

class BaseScanner(ABC):
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass

    @abstractmethod
    async def scan(self, target_dir: Path) -> Dict[str, Any]:
        """
        Execute the scan on target_dir.
        Returns a dict containing results (e.g., raw JSON output or status).
        """
        pass
