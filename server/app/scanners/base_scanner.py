import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Base scanner class that all scanner implementations should inherit from.
    Provides common functionality and defines the scanner interface.
    """

    # Scanner metadata - override in subclasses
    name = "Base Scanner"
    description = "Base scanner class"

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        """
        Initialize the scanner

        Args:
            target_url (str): The URL of the website to scan
            cookies (Optional[str]): Optional cookies string for authenticated scanning
        """
        self.target_url = target_url
        self.cookies = cookies
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.progress = 0  # Progress percentage (0-100)

    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """
        Run the scan and return results

        Returns:
            Dict[str, Any]: Scan results in a standardized format
        """
        pass

    def run(self) -> Dict[str, Any]:
        """
        Execute the scan with proper logging and error handling

        Returns:
            Dict[str, Any]: Scan results
        """
        self.logger.info(f"Starting {self.name} scan for {self.target_url}")
        start_time = self._get_time()

        try:
            results = self.scan()

            # Add scanner metadata to results
            results["scanner"] = self.name
            results["target_url"] = self.target_url
            results["scan_time_ms"] = self._get_time() - start_time

            self.logger.info(
                f"Completed {self.name} scan in {results['scan_time_ms']}ms"
            )
            return results

        except Exception as e:
            self.logger.error(f"Error in {self.name} scan: {str(e)}", exc_info=True)
            return {
                "scanner": self.name,
                "target_url": self.target_url,
                "error": str(e),
                "scan_time_ms": self._get_time() - start_time,
            }

    def get_progress(self) -> int:
        """
        Get the current scan progress percentage (0-100)

        Returns:
            int: Progress percentage
        """
        return self.progress

    def _get_time(self) -> int:
        """Get current time in milliseconds"""
        import time

        return int(time.time() * 1000)
