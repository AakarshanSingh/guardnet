import requests
from requests.exceptions import RequestException
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Set
from bs4 import BeautifulSoup

from app.scanners.base_scanner import BaseScanner


class DirectoryScanner(BaseScanner):
    """
    Scanner to detect directories and sensitive files
    """

    name = "Directory Scanner"
    description = "Scans for directories and sensitive files on the web server"

    # Common directories to check
    COMMON_DIRECTORIES = [
        "/admin",
        "/wp-admin",
        "/administrator",
        "/login",
        "/wp-login.php",
        "/backup",
        "/backups",
        "/bak",
        "/old",
        "/db",
        "/database",
        "/logs",
        "/log",
        "/tmp",
        "/temp",
        "/test",
        "/dev",
        "/config",
        "/conf",
        "/settings",
        "/setup",
        "/install",
        "/wp-content",
        "/wp-includes",
        "/images",
        "/uploads",
        "/files",
        "/css",
        "/js",
        "/javascript",
        "/assets",
        "/static",
        "/media",
        "/api",
        "/rest",
        "/v1",
        "/v2",
        "/api/v1",
        "/api/v2",
    ]

    # Potentially sensitive files
    SENSITIVE_FILES = [
        # Configuration and information files
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/configuration.php",
        "/config.ini",
        "/config.json",
        "/settings.php",
        "/settings.json",
        "/.htaccess",
        "/.htpasswd",
        "/robots.txt",
        "/sitemap.xml",
        # Backup and temporary files
        "/.git/config",
        "/.git/HEAD",
        "/backup.sql",
        "/dump.sql",
        "/db.sql",
        "/database.sql",
        "/backup.zip",
        "/backup.tar.gz",
        "/*.bak",
        "/*.old",
        "/*.swp",
        "/*.tmp",
        # Information disclosure files
        "/README.md",
        "/CHANGELOG.md",
        "/LICENSE",
        "/CONTRIBUTING.md",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/server-status",
        # Default CMS files
        "/wp-login.php",
        "/wp-admin",
        "/administrator",
        "/admin",
        "/joomla.xml",
        "/drupal",
        "/user/login",
        # Common framework files
        "/laravel/.env",
        "/symfony/.env",
        "/index.php.bak",
        "/app/config/parameters.yml",
        "/config/app.php",
        # Log files
        "/logs/errors.log",
        "/logs/access.log",
        "/error_log",
        "/access_log",
        "/debug.log",
        "/app.log",
    ]

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.base_url = self._normalize_url(target_url)
        self.found_directories: List[str] = []
        self.found_sensitive_files: List[Dict[str, Any]] = []
        self.max_threads = 20
        self.request_timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to ensure it ends with a slash"""
        if not url.endswith("/"):
            url += "/"
        return url

    def scan(self) -> Dict[str, Any]:
        """Run directory scan"""
        self.progress = 10

        if self.cookies:
            self._set_cookies()

        try:
            # Extract directories from robots.txt and sitemap.xml
            self._check_common_files()
            self.progress = 20

            # Check common directories
            self._scan_common_directories()
            self.progress = 60

            # Check sensitive files
            self._scan_sensitive_files()
            self.progress = 90

            # Extract additional directories from HTML
            self._extract_directories_from_html()
            self.progress = 100

            return {
                "base_url": self.base_url,
                "directories_found": self.found_directories,
                "sensitive_files_found": self.found_sensitive_files,
            }

        except Exception as e:
            self.logger.error(f"Error in directory scan: {e}")
            return {
                "base_url": self.base_url,
                "directories_found": self.found_directories,
                "sensitive_files_found": self.found_sensitive_files,
                "error": str(e),
            }

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

    def _check_common_files(self):
        """Check robots.txt and sitemap.xml for directory information"""
        try:
            # Check robots.txt
            robots_url = urllib.parse.urljoin(self.base_url, "robots.txt")
            response = self.session.get(robots_url, timeout=self.request_timeout)

            if response.status_code == 200:
                lines = response.text.split("\n")
                for line in lines:
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            directory = urllib.parse.urljoin(self.base_url, path)
                            self.found_directories.append(path)

            # Check sitemap.xml
            sitemap_url = urllib.parse.urljoin(self.base_url, "sitemap.xml")
            response = self.session.get(sitemap_url, timeout=self.request_timeout)

            if response.status_code == 200 and response.headers.get(
                "content-type", ""
            ).startswith("text/xml"):
                soup = BeautifulSoup(response.text, "xml")
                locs = soup.find_all("loc")

                for loc in locs:
                    url = loc.text
                    try:
                        path = urllib.parse.urlparse(url).path
                        if path and path != "/":
                            directory = path.rsplit("/", 1)[0] + "/"
                            if (
                                directory != "/"
                                and directory not in self.found_directories
                            ):
                                self.found_directories.append(directory)
                    except:
                        pass

        except Exception as e:
            self.logger.warning(f"Error checking common files: {e}")

    def _check_url(self, url_path: str) -> Optional[Dict[str, Any]]:
        """
        Check if a URL exists and return status information
        """
        full_url = urllib.parse.urljoin(self.base_url, url_path.lstrip("/"))

        try:
            response = self.session.get(
                full_url, timeout=self.request_timeout, allow_redirects=False
            )

            # Consider 2xx status codes as "found"
            if 200 <= response.status_code < 300:
                return {
                    "url": full_url,
                    "path": url_path,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type", "unknown"),
                    "content_length": len(response.content),
                }
            # Special case for directory listing
            elif response.status_code == 403 and "Index of" in response.text:
                return {
                    "url": full_url,
                    "path": url_path,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type", "unknown"),
                    "content_length": len(response.content),
                    "info": "Directory listing forbidden but exists",
                }

            return None

        except RequestException:
            return None

    def _scan_common_directories(self):
        """Scan for common directories"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(self._check_url, self.COMMON_DIRECTORIES)

            for result in results:
                if result:
                    self.found_directories.append(result["path"])

    def _scan_sensitive_files(self):
        """Scan for sensitive files"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(self._check_url, self.SENSITIVE_FILES)

            for result in results:
                if result:
                    self.found_sensitive_files.append(result)

    def _extract_directories_from_html(self):
        """Extract more directories from the HTML content of the base URL"""
        try:
            response = self.session.get(self.base_url, timeout=self.request_timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")

                # Find all links
                for link in soup.find_all("a", href=True):
                    href = link["href"]

                    # Skip external links and anchors
                    if href.startswith(
                        ("http://", "https://", "mailto:", "tel:", "#", "javascript:")
                    ):
                        continue

                    try:
                        path = urllib.parse.urlparse(href).path
                        if path and path not in ("/", ""):
                            # Try to determine if it's a directory (ends with slash or no extension)
                            if path.endswith("/") or "." not in path.split("/")[-1]:
                                directory = path if path.endswith("/") else path + "/"
                                if directory not in self.found_directories:
                                    self.found_directories.append(directory)
                    except:
                        pass

        except Exception as e:
            self.logger.warning(f"Error extracting directories from HTML: {e}")

    def _assess_security_risks(self) -> List[Dict[str, Any]]:
        """
        Assess security risks based on found directories and files
        """
        risks = []

        # Check for sensitive files
        for file in self.found_sensitive_files:
            path = file["path"]

            # Config files
            if any(
                pattern in path.lower() for pattern in ["config", ".env", ".htaccess"]
            ):
                risks.append(
                    {
                        "severity": "high",
                        "title": "Configuration File Exposed",
                        "description": f"The file {path} may contain sensitive configuration data",
                        "url": file["url"],
                    }
                )

            # Backup files
            elif any(
                pattern in path.lower()
                for pattern in ["backup", ".bak", ".old", "dump", ".sql"]
            ):
                risks.append(
                    {
                        "severity": "high",
                        "title": "Backup File Exposed",
                        "description": f"The file {path} may contain sensitive backup data",
                        "url": file["url"],
                    }
                )

            # Git information
            elif ".git/" in path.lower():
                risks.append(
                    {
                        "severity": "critical",
                        "title": "Git Repository Exposed",
                        "description": "Git repository information is exposed, which may contain source code and credentials",
                        "url": file["url"],
                    }
                )

            # Debug/Information files
            elif any(
                pattern in path.lower()
                for pattern in ["phpinfo", "info.php", "test.php"]
            ):
                risks.append(
                    {
                        "severity": "medium",
                        "title": "Information Disclosure",
                        "description": f"The file {path} may expose system information",
                        "url": file["url"],
                    }
                )

            # Log files
            elif any(pattern in path.lower() for pattern in ["log", "error", "debug"]):
                risks.append(
                    {
                        "severity": "medium",
                        "title": "Log File Exposed",
                        "description": f"The file {path} may contain sensitive log data",
                        "url": file["url"],
                    }
                )

        return risks
