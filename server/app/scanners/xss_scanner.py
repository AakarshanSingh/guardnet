import re
import urllib.parse
import logging
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException

from app.scanners.base_scanner import BaseScanner
from app.utils.browser_manager import browser_manager


class XSSScanner(BaseScanner):
    """
    Scanner to detect Cross-Site Scripting (XSS) vulnerabilities
    """

    name = "XSS Scanner"
    description = (
        "Detects Cross-Site Scripting (XSS) vulnerabilities in web applications"
    )

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<img src=x oneRRor=alert(1)>",
        "<script>prompt(1)</script>",
        "<script>confirm(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "';alert(1);//",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<a href=javascript:alert(1)>click me</a>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<img """><script>alert(1)</script>">',
        '<iframe src="javascript:alert(1)"></iframe>',
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
        "<img src=x onerror=eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    ]

    XSS_DETECTION_PATTERNS = [
        r'<script>alert\((?:1|\'XSS\'|"XSS")\)</script>',
        r'<img[^>]*src\s*=\s*x[^>]*onerror\s*=\s*alert\((?:1|\'XSS\'|"XSS")\)[^>]*>',
        r'<svg[^>]*onload\s*=\s*alert\((?:1|\'XSS\'|"XSS")\)[^>]*>',
        r'<body[^>]*onload\s*=\s*alert\((?:1|\'XSS\'|"XSS")\)[^>]*>',
        r'<input[^>]*onfocus\s*=\s*alert\((?:1|\'XSS\'|"XSS")\)[^>]*>',
        r'<a[^>]*href\s*=\s*javascript:alert\((?:1|\'XSS\'|"XSS")\)[^>]*>',
        r'<iframe[^>]*src\s*=\s*["\']?javascript:alert\((?:1|\'XSS\'|"XSS")\)["\']?[^>]*>',
        r'prompt\((?:1|\'XSS\'|"XSS")\)',
        r'confirm\((?:1|\'XSS\'|"XSS")\)',
    ]

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        self.session = requests.Session()
        self.max_threads = 10
        self.vulnerable_endpoints = []
        self.tested_urls = set()
        self.logger = logging.getLogger(__name__)

        self.browser = None

        self.form_targets = []

    def scan(self) -> Dict[str, Any]:
        """Implementation of the abstract scan method that calls run"""
        return self.run()

    def _get_browser(self):
        """Get the shared browser instance"""
        if not self.browser:
            self.browser = browser_manager.get_browser()
        return self.browser

    def run(self) -> Dict[str, Any]:
        """Run XSS scan using the form targets provided by coordinator"""
        self.progress = 10

        if self.cookies:
            self._set_cookies()

        try:
            self.progress = 20

            if self.form_targets:
                self.logger.info(
                    f"Using {len(self.form_targets)} targets provided by coordinator"
                )

                endpoints = self._prepare_form_targets()
            else:

                self.logger.info("No targets from coordinator, crawling website")
                endpoints = self._crawl_website()

            self.progress = 30

            if endpoints:
                self._test_endpoints(endpoints)

            self.progress = 100
            return {
                "vulnerable_endpoints": self.vulnerable_endpoints,
                "payloads_used": self.PAYLOADS,
            }

        except Exception as e:
            self.logger.error(f"Error in XSS scan: {e}")
            return {
                "error": str(e),
                "vulnerable_endpoints": self.vulnerable_endpoints,
                "payloads_used": self.PAYLOADS,
            }

    def _prepare_form_targets(self) -> List[Dict[str, Any]]:
        """Transform coordinator-provided targets into the format expected by _test_endpoints"""
        form_targets = []

        try:
            for target in self.form_targets:
                url = target.get("url", "")
                method = target.get("method", "get").lower()

                params = target.get("params", {})
                if isinstance(params, list):

                    param_dict = {}
                    for param_name in params:
                        param_dict[param_name] = "test"
                    params = param_dict

                if params:
                    form_targets.append(
                        {
                            "url": url,
                            "method": method,
                            "params": params,
                            "context": "coordinator",
                        }
                    )

            return form_targets

        except Exception as e:
            self.logger.error(f"Error preparing form targets: {e}")
            return []

    def _set_cookies(self):
        """Set cookies in both session and browser"""
        if not self.cookies:
            return

        cookie_pairs = self.cookies.split(";")
        for cookie_pair in cookie_pairs:
            if "=" in cookie_pair:
                name, value = cookie_pair.strip().split("=", 1)
                self.session.cookies.set(name, value)

        browser = self._get_browser()
        try:

            browser_manager.safe_get(self.target_url)

            for cookie_pair in self.cookies.split(";"):
                if "=" in cookie_pair:
                    name, value = cookie_pair.strip().split("=", 1)
                    browser.add_cookie(
                        {
                            "name": name,
                            "value": value,
                            "domain": urllib.parse.urlparse(self.target_url).netloc,
                        }
                    )

        except Exception as e:
            self.logger.error(f"Error setting browser cookies: {e}")

    def _crawl_website(self) -> List[Dict[str, Any]]:
        """Crawl website to find forms and inputs"""
        forms_and_inputs = []
        visited_urls = set()
        urls_to_visit = [self.target_url]
        max_pages = 20

        try:

            browser = self._get_browser()

            while urls_to_visit and len(visited_urls) < max_pages:
                current_url = urls_to_visit.pop(0)

                if current_url in visited_urls:
                    continue

                visited_urls.add(current_url)

                try:

                    success = browser_manager.safe_get(current_url)

                    if success:
                        soup = BeautifulSoup(browser.page_source, "html.parser")
                    else:

                        self.logger.debug(f"Falling back to requests for {current_url}")
                        response = self.session.get(
                            current_url, headers=self.headers, timeout=10
                        )

                        if response.status_code != 200:
                            continue

                        soup = BeautifulSoup(response.text, "html.parser")

                    for form in soup.find_all("form"):
                        form_action = form.get("action", "")
                        form_method = form.get("method", "get").lower()
                        form_url = urllib.parse.urljoin(current_url, form_action)

                        inputs = {}
                        for input_tag in form.find_all(["input", "textarea"]):
                            input_name = input_tag.get("name")
                            if input_name:
                                inputs[input_name] = input_tag.get("value", "")

                        if inputs:
                            forms_and_inputs.append(
                                {
                                    "url": form_url,
                                    "method": form_method,
                                    "params": inputs,
                                    "context": "form",
                                }
                            )

                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        if href.startswith("javascript:") or href.startswith("#"):
                            continue

                        full_url = urllib.parse.urljoin(current_url, href)
                        parsed_url = urllib.parse.urlparse(full_url)

                        if (
                            urllib.parse.urlparse(self.target_url).netloc
                            != parsed_url.netloc
                        ):
                            continue

                        if (
                            full_url not in visited_urls
                            and full_url not in urls_to_visit
                        ):
                            urls_to_visit.append(full_url)

                        if parsed_url.query:
                            query_params = dict(
                                urllib.parse.parse_qsl(parsed_url.query)
                            )
                            forms_and_inputs.append(
                                {
                                    "url": full_url.split("?")[0],
                                    "method": "get",
                                    "params": query_params,
                                    "context": "url",
                                }
                            )

                except Exception as e:
                    self.logger.debug(f"Error crawling {current_url}: {e}")

            self.logger.info(
                f"Crawled {len(visited_urls)} pages, found {len(forms_and_inputs)} potential endpoints"
            )
            return forms_and_inputs

        except Exception as e:
            self.logger.error(f"Error in website crawling: {e}")
            return []

    def _test_endpoints(self, endpoints: List[Dict[str, Any]]):
        """Test endpoints for XSS vulnerabilities"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []

            for endpoint in endpoints:
                url = endpoint["url"]
                method = endpoint["method"]
                params = endpoint["params"]

                for param_name in params.keys():
                    for payload in self.PAYLOADS:

                        test_params = params.copy()
                        test_params[param_name] = payload

                        if method.lower() == "get":
                            futures.append(
                                executor.submit(
                                    self._test_get_endpoint,
                                    url,
                                    test_params,
                                    param_name,
                                    payload,
                                )
                            )
                        elif method.lower() == "post":
                            futures.append(
                                executor.submit(
                                    self._test_post_endpoint,
                                    url,
                                    test_params,
                                    param_name,
                                    payload,
                                )
                            )

            completed = 0
            for future in futures:
                future.result()
                completed += 1

                self.progress = 30 + int(60 * (completed / len(futures)))

    def _test_get_endpoint(
        self, url: str, params: Dict[str, Any], param_name: str, payload: str
    ):
        """Test a GET endpoint for XSS using both browser and requests"""
        try:
            cache_key = f"{url}?{urllib.parse.urlencode(params)}"

            if cache_key in self.tested_urls:
                return

            self.tested_urls.add(cache_key)

            browser = self._get_browser()
            try:
                full_url = f"{url}?{urllib.parse.urlencode(params)}"
                success = browser_manager.safe_get(full_url)

                if success:
                    content = browser.page_source

                    self._analyze_response(
                        {"text": content, "status_code": 200},
                        url,
                        "GET",
                        param_name,
                        payload,
                    )
                    return
            except (TimeoutException, WebDriverException) as e:
                self.logger.debug(
                    f"Browser error for {url}, falling back to requests: {e}"
                )

            response = self.session.get(
                url, params=params, headers=self.headers, timeout=10
            )

            self._analyze_response(response, url, "GET", param_name, payload)

        except Exception as e:
            self.logger.debug(f"Error testing GET endpoint {url}: {e}")

    def _test_post_endpoint(
        self, url: str, data: Dict[str, Any], param_name: str, payload: str
    ):
        """Test a POST endpoint for XSS using both browser and requests"""
        try:
            cache_key = f"POST {url} {urllib.parse.urlencode(data)}"

            if cache_key in self.tested_urls:
                return

            self.tested_urls.add(cache_key)

            browser = self._get_browser()
            try:

                browser_manager.safe_get(url)

                try:

                    for field_name, field_value in data.items():
                        try:
                            input_field = browser.find_element(By.NAME, field_name)
                            input_field.clear()
                            input_field.send_keys(field_value)
                        except Exception as e:
                            self.logger.debug(f"Could not fill field {field_name}: {e}")

                    forms = browser.find_elements(By.TAG_NAME, "form")
                    if forms:
                        forms[0].submit()
                        content = browser.page_source

                        self._analyze_response(
                            {"text": content, "status_code": 200},
                            url,
                            "POST",
                            param_name,
                            payload,
                        )
                        return
                except Exception as form_ex:
                    self.logger.debug(f"Error submitting form in browser: {form_ex}")
            except (TimeoutException, WebDriverException) as e:
                self.logger.debug(
                    f"Browser error for POST to {url}, falling back to requests: {e}"
                )

            response = self.session.post(
                url, data=data, headers=self.headers, timeout=10
            )

            self._analyze_response(response, url, "POST", param_name, payload)

        except Exception as e:
            self.logger.debug(f"Error testing POST endpoint {url}: {e}")

    def _analyze_response(
        self, response, url: str, method: str, param_name: str, payload: str
    ):
        """Analyze response for XSS vulnerabilities"""
        try:

            if hasattr(response, "text"):
                content = response.text
            else:
                content = response["text"]

            if payload in content:

                soup = BeautifulSoup(content, "html.parser")

                for pattern in self.XSS_DETECTION_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        self._add_vulnerability(
                            url,
                            method,
                            param_name,
                            payload,
                            "high",
                            "Direct payload reflection",
                        )
                        return

                if self._check_dangerous_contexts(soup, payload):
                    self._add_vulnerability(
                        url,
                        method,
                        param_name,
                        payload,
                        "high",
                        "Found in dangerous context",
                    )
                    return

                self._add_vulnerability(
                    url,
                    method,
                    param_name,
                    payload,
                    "medium",
                    "Payload reflected but may not be executable",
                )

        except Exception as e:
            self.logger.debug(f"Error analyzing response: {e}")

    def _check_dangerous_contexts(self, soup: BeautifulSoup, payload: str) -> bool:
        """Check if payload is in a dangerous context where XSS might execute"""

        for script in soup.find_all("script"):
            if payload in script.string:
                return True

        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.lower().startswith("on") and payload in tag[attr]:
                    return True

        for a_tag in soup.find_all("a", href=True):
            if payload in a_tag["href"] and a_tag["href"].lower().startswith(
                "javascript:"
            ):
                return True

        for tag in soup.find_all(["img", "iframe"]):
            if tag.has_attr("src") and payload in tag["src"]:
                return True

        return False

    def _add_vulnerability(
        self,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        severity: str,
        details: str,
    ):
        """Add a vulnerability to the list if not already present"""

        for vuln in self.vulnerable_endpoints:
            if vuln["url"] == url and vuln["parameter"] == param_name:
                if severity == "high" and vuln["severity"] != "high":

                    vuln["severity"] = severity
                    vuln["payload"] = payload
                    vuln["details"] = details
                return

        vulnerability = {
            "url": url,
            "method": method,
            "parameter": param_name,
            "payload": payload,
            "severity": severity,
            "details": details,
        }

        self.vulnerable_endpoints.append(vulnerability)
        self.logger.warning(
            f"Found XSS vulnerability: {url}, parameter: {param_name}, severity: {severity}"
        )
