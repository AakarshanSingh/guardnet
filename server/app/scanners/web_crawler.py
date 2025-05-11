import logging
import re
import time
import urllib.parse
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urlparse, parse_qsl, urljoin, urlunparse
import threading
from queue import Queue, Empty
import json

from bs4 import BeautifulSoup
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
    NoSuchElementException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from app.utils.browser_manager import browser_manager
from app.core.config import settings

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Advanced web crawler that extracts URLs, forms and input fields from websites using Selenium.
    Designed to identify potential targets for vulnerability scanning.
    """

    def __init__(
        self,
        base_url: str,
        cookies: Optional[str] = None,
        max_pages: int = 100,
        max_depth: int = 3,
        scan_external: bool = False,
        threads: int = 5,
    ):
        """
        Initialize the web crawler.

        Args:
            base_url: The starting URL to crawl from
            cookies: Optional cookies string in format "name1=value1; name2=value2"
            max_pages: Maximum number of pages to crawl
            max_depth: Maximum depth to crawl
            scan_external: Whether to follow links to external domains
            threads: Number of worker threads for crawling
        """
        self.base_url = base_url
        self.cookies = cookies
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.scan_external = scan_external

        # Tracking collections
        self.visited_urls: Set[str] = set()
        self.url_queue = Queue()
        self.forms_found: List[Dict[str, Any]] = []
        self.inputs_found: List[Dict[str, Any]] = []
        self.links_found: Dict[str, List[str]] = {}
        self.parameters_found: Dict[str, List[str]] = {}

        # Scanning flags
        self.scanning = True
        self.threads_count = threads
        self.workers = []

        # Mutex for thread-safe operations
        self.lock = threading.RLock()

    def set_cookies(self):
        """Set cookies in the browser if provided"""
        if not self.cookies:
            return

        try:
            browser = browser_manager.get_browser()
            # First navigate to the domain to set cookies
            browser_manager.safe_get(self.base_url)

            # Parse and add cookies
            for cookie in self.cookies.split(";"):
                if "=" in cookie:
                    name, value = cookie.strip().split("=", 1)
                    try:
                        # Extract the domain from base_url for the cookie
                        domain = urlparse(self.base_url).netloc

                        # Remove port number if present
                        if ":" in domain:
                            domain = domain.split(":")[0]

                        # Add cookie with proper domain setting
                        browser.add_cookie(
                            {"name": name, "value": value, "domain": domain}
                        )
                        logger.info(
                            f"Cookie set successfully: {name}={value[:3]}*** for domain: {domain}"
                        )
                    except Exception as cookie_error:
                        logger.warning(
                            f"Failed to set individual cookie {name}: {str(cookie_error)}"
                        )

            browser.refresh()
            logger.info(f"Cookies process completed for domain: {self.base_domain}")

        except Exception as e:
            logger.error(f"Error setting cookies: {str(e)}")

    def start_crawl(self):
        """Start the crawling process with multiple threads"""
        self.set_cookies()
        self.url_queue.put((self.base_url, 0))

        for i in range(self.threads_count):
            worker = threading.Thread(target=self._crawl_worker, name=f"crawler-{i}")
            worker.daemon = True
            worker.start()
            self.workers.append(worker)

        for worker in self.workers:
            worker.join()

        logger.info(f"Crawling completed. Visited {len(self.visited_urls)} pages.")
        return self._get_results()

    def _crawl_worker(self):
        """Worker thread for crawling pages"""
        while self.scanning:
            try:
                url, depth = self.url_queue.get(timeout=5)

                with self.lock:
                    if len(self.visited_urls) >= self.max_pages:
                        self.scanning = False
                        self.url_queue.task_done()
                        break

                if url in self.visited_urls or depth > self.max_depth:
                    self.url_queue.task_done()
                    continue

                self._process_page(url, depth)
                self.url_queue.task_done()

            except Empty:
                with self.lock:
                    if self.url_queue.empty():
                        break
            except Exception as e:
                logger.error(f"Error in crawler worker: {str(e)}")
                self.url_queue.task_done()

    def _process_page(self, url: str, depth: int):
        """Process a single page: extract links, forms, and inputs"""
        logger.info(f"Crawling: {url} (depth: {depth})")

        with self.lock:
            self.visited_urls.add(url)

        # Load the page with Selenium
        browser = browser_manager.get_browser()
        if not browser_manager.safe_get(url):
            logger.warning(f"Failed to load page: {url}")
            return

        try:

            time.sleep(1)

            page_content = browser.page_source
            soup = BeautifulSoup(page_content, "html.parser")

            self._extract_links(soup, url, depth)
            self._extract_forms(soup, url)
            self._extract_inputs(soup, url)
            self._extract_api_endpoints(page_content, url)

            parsed_url = urlparse(url)
            if parsed_url.query:
                params = dict(parse_qsl(parsed_url.query))
                with self.lock:
                    if url not in self.parameters_found:
                        self.parameters_found[url] = []
                    for param in params:
                        if param not in self.parameters_found[url]:
                            self.parameters_found[url].append(param)

        except Exception as e:
            logger.error(f"Error processing page {url}: {str(e)}")

    def _extract_links(self, soup: BeautifulSoup, current_url: str, depth: int):
        """Extract links from the page and add them to the crawl queue"""
        links = []
        try:
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                link_text = a_tag.get_text().lower().strip()

                # Skip empty, javascript and anchor links
                if not href or href.startswith("javascript:") or href == "#":
                    continue

                # Skip logout/signout links to avoid logging out during crawling
                logout_keywords = [
                    "logout",
                    "log out",
                    "signout",
                    "sign out",
                    "log off",
                    "logoff",
                    "sign-out",
                    "sign-off",
                ]
                if any(keyword in href.lower() for keyword in logout_keywords) or any(
                    keyword in link_text for keyword in logout_keywords
                ):
                    logger.info(f"Skipping potential logout link: {href}")
                    continue

                # Normalize the URL
                full_url = urljoin(current_url, href)
                parsed_url = urlparse(full_url)

                # Clean up the URL - remove fragments and normalize
                clean_url = urlunparse(
                    (
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        parsed_url.query,
                        "",  # Remove fragment
                    )
                )

                # Skip links outside the base domain if not scanning external sites
                if not self.scan_external and parsed_url.netloc != self.base_domain:
                    continue

                # Add the URL to our results and queue
                with self.lock:
                    if current_url not in self.links_found:
                        self.links_found[current_url] = []
                    if clean_url not in self.links_found[current_url]:
                        self.links_found[current_url].append(clean_url)

                    # Add to queue if not visited
                    if (
                        clean_url not in self.visited_urls
                        and depth + 1 <= self.max_depth
                    ):
                        links.append(clean_url)
                        self.url_queue.put((clean_url, depth + 1))

        except Exception as e:
            logger.error(f"Error extracting links from {current_url}: {str(e)}")

        return links

    def _extract_forms(self, soup: BeautifulSoup, url: str):
        """Extract forms from the page"""
        try:
            for form in soup.find_all("form"):
                form_data = {
                    "url": url,
                    "action": urljoin(url, form.get("action", "")),
                    "method": form.get("method", "get").lower(),
                    "inputs": [],
                }

                # Extract form inputs
                for input_field in form.find_all(["input", "textarea", "select"]):
                    input_type = input_field.get("type", "")
                    input_name = input_field.get("name", "")

                    # Skip buttons, submits, and unnamed fields
                    if (
                        input_type in ["button", "submit", "reset", "image"]
                        or not input_name
                    ):
                        continue

                    form_data["inputs"].append({"name": input_name, "type": input_type})

                # Only add forms that have inputs
                if form_data["inputs"]:
                    with self.lock:
                        self.forms_found.append(form_data)
        except Exception as e:
            logger.error(f"Error extracting forms from {url}: {str(e)}")

    def _extract_inputs(self, soup: BeautifulSoup, url: str):
        """Extract inputs outside of forms that might be used in AJAX requests"""
        try:
            for input_tag in soup.find_all(["input", "textarea", "select"]):
                if not input_tag.parent or input_tag.parent.name != "form":
                    input_name = input_tag.get("name", "")
                    if not input_name:
                        continue

                    input_data = {
                        "url": url,
                        "name": input_name,
                        "type": input_tag.get("type", "text"),
                    }

                    with self.lock:
                        self.inputs_found.append(input_data)
        except Exception as e:
            logger.error(f"Error extracting inputs from {url}: {str(e)}")

    def _extract_api_endpoints(self, content: str, url: str):
        """Extract API endpoints and URLs from JavaScript code"""
        try:
            # Look for URLs in JavaScript
            url_pattern = r'(https?:\/\/[^\s\'"]+)'
            api_pattern = r'(\/api\/[^\s\'"]+)'

            urls = re.findall(url_pattern, content)
            apis = re.findall(api_pattern, content)

            for found_url in urls + apis:
                # Normalize and clean the URL
                full_url = urljoin(url, found_url)
                parsed = urlparse(full_url)

                # Skip URLs outside the base domain if not scanning external
                if not self.scan_external and parsed.netloc != self.base_domain:
                    continue

                # Add to queue if not visited and looks like a valid endpoint
                # Check if URL looks like an API endpoint or resource URL
                if (
                    parsed.path.endswith(".json")
                    or "/api/" in parsed.path
                    or any(
                        keyword in parsed.path
                        for keyword in ["get", "fetch", "load", "data"]
                    )
                ):

                    clean_url = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            parsed.query,
                            "",
                        )
                    )

                    # Add to queue
                    with self.lock:
                        if clean_url not in self.visited_urls:
                            self.url_queue.put(
                                (clean_url, self.max_depth)
                            )  # Check APIs at max depth
        except Exception as e:
            logger.error(f"Error extracting API endpoints from {url}: {str(e)}")

    def _get_results(self) -> Dict[str, Any]:
        """Get the crawling results"""
        return {
            "base_url": self.base_url,
            "pages_crawled": len(self.visited_urls),
            "visited_urls": list(self.visited_urls),
            "forms_found": self.forms_found,
            "inputs_found": self.inputs_found,
            "parameters_found": self.parameters_found,
        }

    def stop_crawl(self):
        """Stop the crawling process"""
        logger.info("Stopping crawler...")
        self.scanning = False

        # Wait for threads to finish
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=2)

        logger.info("Crawler stopped")
