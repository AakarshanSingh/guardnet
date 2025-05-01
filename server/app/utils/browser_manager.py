import os
import logging
import time
import urllib.parse
import urllib3
from typing import Optional
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import (
    WebDriverException,
    TimeoutException,
    SessionNotCreatedException,
    InvalidSessionIdException,
    NoSuchWindowException,
)
from urllib3.exceptions import NewConnectionError, MaxRetryError

logger = logging.getLogger(__name__)


class BrowserManager:
    """
    Singleton class to manage a single Selenium browser instance across the application.
    This ensures we don't create multiple browser instances, improving efficiency.
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds
    REQUEST_PAUSE = 1  # seconds to pause after each request

    def __init__(self):
        self._browser = None
        self._options = None
        self._initialize_options()

    def _initialize_options(self):
        """Initialize Chrome options for headless browsing"""
        self._options = Options()
        # Use headless mode for production, uncomment for deployment
        # self._options.add_argument("--headless=new")  # Updated headless syntax
        self._options.add_argument("--disable-gpu")
        self._options.add_argument("--no-sandbox")
        self._options.add_argument("--disable-dev-shm-usage")
        self._options.add_argument("--disable-extensions")
        self._options.add_argument("--disable-infobars")
        self._options.add_argument("--ignore-certificate-errors")
        self._options.add_argument("--ignore-ssl-errors")
        self._options.add_argument("--disable-popup-blocking")
        self._options.add_argument("--window-size=1920,1080")
        # Add more specific options to prevent connection issues
        self._options.add_argument("--disable-application-cache")
        self._options.add_argument("--disable-web-security")
        self._options.add_argument("--disable-logging")
        self._options.add_argument("--disable-background-networking")
        # Settings to help with connection pool issues
        self._options.add_argument("--dns-prefetch-disable")
        self._options.add_argument("--disable-features=NetworkService")
        self._options.add_argument("--force-device-scale-factor=1")
        # Keep-alive settings to manage connections better
        self._options.add_argument("--disable-features=IsolateOrigins,site-per-process")
        self._options.add_argument(
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )

    def get_browser(self) -> webdriver.Chrome:
        """
        Get the browser instance, creating it if it doesn't exist or has crashed.
        Includes retry logic for reliability.

        Returns:
            webdriver.Chrome: The Chrome browser instance
        """
        if self._browser is None:
            return self._create_browser_with_retry()
        else:
            # Check if browser is still responsive
            try:
                # Simple operation to check if browser is alive
                _ = self._browser.window_handles
                return self._browser
            except (WebDriverException, Exception) as e:
                logger.warning(
                    f"Browser instance has crashed or is unresponsive, creating new instance: {str(e)}"
                )
                self.close_browser()  # Clean up any remaining resources
                return self._create_browser_with_retry()

    def _create_browser_with_retry(self) -> webdriver.Chrome:
        """Create browser with retry logic for better reliability"""
        retries = 0
        last_exception = None

        while retries < self.MAX_RETRIES:
            try:
                self._create_browser()
                return self._browser
            except (WebDriverException, SessionNotCreatedException) as e:
                last_exception = e
                retries += 1
                logger.warning(
                    f"Browser creation attempt {retries}/{self.MAX_RETRIES} failed: {str(e)}"
                )
                # Wait before retrying
                time.sleep(self.RETRY_DELAY)

                # Force kill any remaining chromedriver processes before retry
                self._force_kill_browser_processes()

        # If we get here, all retries failed
        logger.error(f"Failed to create browser after {self.MAX_RETRIES} attempts")
        if last_exception:
            raise RuntimeError(
                f"Browser creation failed: {str(last_exception)}"
            ) from last_exception
        else:
            raise RuntimeError("Browser creation failed for unknown reasons")

    def _create_browser(self):
        """Create a new browser instance with configured options"""
        try:
            logger.info("Creating new browser instance")

            # Create Service with extra parameters to help with connection issues
            service = Service(log_path=os.devnull)

            self._browser = webdriver.Chrome(options=self._options, service=service)
            self._browser.set_page_load_timeout(30)  # 30 seconds timeout for page loads

            # Set default connection settings
            self._browser.execute_cdp_cmd(
                "Network.setCacheDisabled", {"cacheDisabled": True}
            )

            logger.info("Browser instance created successfully")
        except Exception as e:
            logger.error(f"Failed to create browser instance: {str(e)}")
            self._browser = None
            raise

    def close_browser(self):
        """Close the browser instance if it exists"""
        if self._browser is not None:
            try:
                logger.info("Closing browser instance")
                # Check if browser is still alive before attempting to quit
                try:
                    # Short timeout for connection attempts
                    self._browser.set_page_load_timeout(5)

                    # Use a very brief operation to test if session is valid
                    try:
                        _ = self._browser.window_handles
                        # If we get here, browser is responsive
                        self._browser.quit()
                        logger.info("Browser quit command executed successfully")
                    except (InvalidSessionIdException, NoSuchWindowException) as e:
                        logger.warning(f"Browser session already invalid: {str(e)}")
                        self._force_kill_browser_processes()
                except (
                    ConnectionError,
                    NewConnectionError,
                    MaxRetryError,
                    urllib3.exceptions.ReadTimeoutError,
                    TimeoutException,
                    WebDriverException,
                ) as e:
                    # These exceptions indicate the browser is already closed or unreachable
                    logger.warning(f"Browser connection failed during close: {str(e)}")
                    # Ensure any remaining processes are terminated
                    self._force_kill_browser_processes()

            except Exception as e:
                logger.warning(f"Error during browser closing: {str(e)}")
                self._force_kill_browser_processes()
            finally:
                self._browser = None
                logger.info("Browser instance set to None")

    def _force_kill_browser_processes(self):
        """Force kill any orphaned Chrome processes as a last resort"""
        try:
            # This is Windows-specific
            if os.name == "nt":
                logger.info("Attempting to force kill Chrome driver processes")
                os.system("taskkill /f /im chromedriver.exe >nul 2>&1")
                # Don't kill chrome.exe as it might affect user's browser sessions
                # We only target ChromeDriver processes
        except Exception as e:
            logger.error(f"Failed to force kill browser processes: {str(e)}")

    def refresh_browser(self):
        """Force refresh the browser instance by closing and creating a new one"""
        self.close_browser()
        # Add a small delay before creating a new browser
        time.sleep(1)
        return self.get_browser()

    def safe_get(self, url: str, timeout: int = 30) -> bool:
        """
        Safely navigate to a URL with error handling and pause after request

        Args:
            url: The URL to navigate to
            timeout: Page load timeout in seconds

        Returns:
            bool: True if navigation was successful, False otherwise
        """
        for attempt in range(2):  # Try twice before giving up
            try:
                browser = self.get_browser()
                browser.set_page_load_timeout(timeout)
                browser.get(url)

                # Add mandatory pause after each request to prevent overwhelming the browser
                time.sleep(self.REQUEST_PAUSE)

                return True
            except TimeoutException:
                logger.warning(f"Page load timeout for URL: {url}")
                time.sleep(self.REQUEST_PAUSE)  # Pause on error too
                return False
            except (
                WebDriverException,
                ConnectionError,
                NewConnectionError,
                MaxRetryError,
            ) as e:
                logger.error(f"Browser connection error navigating to {url}: {str(e)}")
                time.sleep(self.REQUEST_PAUSE)  # Pause on error too
                if attempt == 0:  # Only refresh on first attempt
                    logger.info("Refreshing browser and retrying...")
                    self.refresh_browser()
                else:
                    return False
            except Exception as e:
                logger.error(f"Unexpected error navigating to {url}: {str(e)}")
                time.sleep(self.REQUEST_PAUSE)  # Pause on error too
                return False

        return False

    def execute_script(self, script: str, *args):
        """
        Safely execute JavaScript in the browser with mandatory pause and error handling

        Args:
            script: JavaScript to execute
            *args: Arguments to pass to the script

        Returns:
            Any: Result of JavaScript execution, or None on error
        """
        try:
            browser = self.get_browser()
            result = browser.execute_script(script, *args)

            # Add mandatory pause after execution
            time.sleep(self.REQUEST_PAUSE)

            return result
        except Exception as e:
            logger.error(f"Error executing script: {str(e)}")
            time.sleep(self.REQUEST_PAUSE)  # Pause on error too
            return None


# Create a single instance of the browser manager
browser_manager = BrowserManager()
