import re
import requests
import urllib.parse
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
from app.scanners.base_scanner import BaseScanner
from app.core.config import settings


class WordPressScanner(BaseScanner):
    """
    Scanner to detect WordPress websites and vulnerabilities
    """

    name = "WordPress Scanner"
    description = "Detects WordPress installations and checks for vulnerabilities"

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.is_wordpress = False
        self.version = None
        self.plugins = []
        self.themes = []
        self.vulnerabilities = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.wpscan_api_key = settings.WPSCAN_API_TOKEN
        self.api_url = "https://wpscan.com/api/v3"

        self.page_content = ""

    def scan(self) -> Dict[str, Any]:
        """Run WordPress scan"""
        self.progress = 10

        if self.cookies:
            self._set_cookies()

        try:
            response = self.session.get(self.target_url, timeout=10)
            self.page_content = response.text
        except Exception as e:
            self.logger.error(f"Error fetching target URL: {e}")
            return {"is_wordpress": False, "error": str(e)}

        is_wp = self._detect_wordpress()
        self.progress = 30

        if not is_wp:
            return {"is_wordpress": False}

        self._detect_version()
        self.progress = 50

        self._detect_themes()
        self.progress = 70

        self._detect_plugins()
        self.progress = 80

        self._check_vulnerabilities()
        self.progress = 100

        return {
            "is_wordpress": True,
            "version": self.version,
            "plugins": self.plugins,
            "themes": self.themes,
            "vulnerabilities": self.vulnerabilities,
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

    def _detect_wordpress(self) -> bool:
        """Detect if website is WordPress using HTTP requests"""
        try:
            html_content = self.page_content.lower()

            meta_wp = re.search(
                r'<meta\s+name=[\'"]generator[\'"] content=[\'"]WordPress\s([0-9.]+)',
                self.page_content,
            )
            if meta_wp:
                self.is_wordpress = True
                self.version = meta_wp.group(1)
                return True

            if "wp-content" in html_content or "wp-includes" in html_content:
                self.is_wordpress = True
                return True

            admin_url = urllib.parse.urljoin(self.target_url, "wp-login.php")
            response = self.session.get(admin_url, timeout=10)
            if response.status_code == 200 and "wordpress" in response.text.lower():
                self.is_wordpress = True
                return True

            rest_url = urllib.parse.urljoin(self.target_url, "wp-json/")
            try:
                response = self.session.get(rest_url, timeout=10)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "name" in data:
                            self.is_wordpress = True
                            return True
                    except:
                        pass
            except:
                pass

            return False

        except Exception as e:
            self.logger.error(f"Error detecting WordPress: {e}")
            return False

    def _detect_version(self):
        """Detect WordPress version"""
        if self.version:
            return

        try:

            readme_url = urllib.parse.urljoin(self.target_url, "readme.html")
            try:
                response = self.session.get(readme_url, timeout=10)
                if response.status_code == 200:
                    version_match = re.search(r"Version\s([0-9.]+)", response.text)
                    if version_match:
                        self.version = version_match.group(1)
                        return
            except:
                pass

            version_patterns = [
                r"ver=([0-9.]+)",
                r"wp-includes/js/wp-emoji-release.min.js\?ver=([0-9.]+)",
                r"wp-includes/css/dist/block-library/style.min.css\?ver=([0-9.]+)",
            ]

            for pattern in version_patterns:
                match = re.search(pattern, self.page_content)
                if match:
                    self.version = match.group(1)
                    return

            feed_url = urllib.parse.urljoin(self.target_url, "feed/")
            try:
                response = self.session.get(feed_url, timeout=10)
                if response.status_code == 200:
                    version_match = re.search(
                        r"generator=\"WordPress\s([0-9.]+)\"", response.text
                    )
                    if version_match:
                        self.version = version_match.group(1)
                        return
            except:
                pass

        except Exception as e:
            self.logger.error(f"Error detecting WordPress version: {e}")

    def _detect_plugins(self):
        """Detect WordPress plugins"""
        try:

            soup = BeautifulSoup(self.page_content, "html.parser")

            plugin_pattern = r"wp-content/plugins/([^/]+)/"
            found_plugins = set(re.findall(plugin_pattern, self.page_content))

            for plugin_slug in found_plugins:
                plugin_info = {
                    "name": plugin_slug.replace("-", " ").title(),
                    "slug": plugin_slug,
                    "version": "Unknown",
                }

                version_pattern = (
                    rf"plugins/{re.escape(plugin_slug)}[^?]*\?ver=([0-9.]+)"
                )
                version_match = re.search(version_pattern, self.page_content)
                if version_match:
                    plugin_info["version"] = version_match.group(1)

                self.plugins.append(plugin_info)

            for plugin_info in self.plugins:
                plugin_slug = plugin_info["slug"]
                readme_url = urllib.parse.urljoin(
                    self.target_url, f"wp-content/plugins/{plugin_slug}/readme.txt"
                )

                try:
                    response = self.session.get(readme_url, timeout=5)
                    if response.status_code == 200:

                        name_match = re.search(r"===\s*([^=]+)\s*===", response.text)
                        if name_match:
                            plugin_info["name"] = name_match.group(1).strip()

                        version_match = re.search(
                            r"Stable tag:\s*([0-9.]+)", response.text
                        )
                        if version_match and plugin_info["version"] == "Unknown":
                            plugin_info["version"] = version_match.group(1)
                except:
                    pass

        except Exception as e:
            self.logger.error(f"Error detecting WordPress plugins: {e}")

    def _detect_themes(self):
        """Detect WordPress themes"""
        try:

            theme_pattern = r"wp-content/themes/([^/]+)/"
            found_themes = set(re.findall(theme_pattern, self.page_content))

            for theme_slug in found_themes:
                theme_info = {
                    "name": theme_slug.replace("-", " ").title(),
                    "slug": theme_slug,
                    "version": "Unknown",
                }

                version_pattern = rf"themes/{re.escape(theme_slug)}[^?]*\?ver=([0-9.]+)"
                version_match = re.search(version_pattern, self.page_content)
                if version_match:
                    theme_info["version"] = version_match.group(1)

                self.themes.append(theme_info)

            for theme_info in self.themes:
                theme_slug = theme_info["slug"]
                style_url = urllib.parse.urljoin(
                    self.target_url, f"wp-content/themes/{theme_slug}/style.css"
                )

                try:
                    response = self.session.get(style_url, timeout=5)
                    if response.status_code == 200:

                        name_match = re.search(r"Theme Name:\s*(.+)", response.text)
                        if name_match:
                            theme_info["name"] = name_match.group(1).strip()

                        version_match = re.search(
                            r"Version:\s*([0-9.]+)", response.text
                        )
                        if version_match and theme_info["version"] == "Unknown":
                            theme_info["version"] = version_match.group(1)
                except:
                    pass

        except Exception as e:
            self.logger.error(f"Error detecting WordPress themes: {e}")

    def _check_vulnerabilities(self):
        """Check for vulnerabilities in WordPress, plugins, and themes"""

        if not self.wpscan_api_key:
            self.logger.warning(
                "No WPScan API key configured. Skipping vulnerability check."
            )
            self.vulnerabilities.append(
                {
                    "component_type": "info",
                    "component_name": "WPScan API Key Missing",
                    "component_version": "N/A",
                    "severity": "low",
                    "title": "WPScan API Key Missing",
                    "description": "Configure a WPScan API key for more detailed vulnerability information.",
                }
            )
            return

        try:

            if self.version:
                self._check_core_vulnerabilities()

            for plugin in self.plugins:
                self._check_plugin_vulnerabilities(plugin)

            for theme in self.themes:
                self._check_theme_vulnerabilities(theme)

        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities: {e}")
            self.vulnerabilities.append(
                {
                    "component_type": "error",
                    "component_name": "API",
                    "component_version": "N/A",
                    "severity": "low",
                    "title": "Vulnerability Check Error",
                    "description": f"Error checking vulnerabilities: {str(e)}",
                }
            )

    def _check_core_vulnerabilities(self):
        """Check WordPress core vulnerabilities"""
        if not self.version:
            return

        try:
            url = f"{self.api_url}/wordpresses/{self.version}"
            response = requests.get(
                url,
                headers={"Authorization": f"Token token={self.wpscan_api_key}"},
                timeout=20,
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("vulnerabilities"):
                    for vuln in data["vulnerabilities"]:
                        self.vulnerabilities.append(
                            {
                                "component_type": "core",
                                "component_name": "WordPress",
                                "component_version": self.version,
                                "severity": vuln.get("severity", "unknown"),
                                "title": vuln.get("title", "Unknown Vulnerability"),
                                "description": vuln.get("description", ""),
                                "fixed_in": vuln.get("fixed_in", ""),
                                "references": vuln.get("references", {}),
                            }
                        )

        except Exception as e:
            self.logger.error(f"Error checking core vulnerabilities: {e}")

    def _check_plugin_vulnerabilities(self, plugin):
        """Check plugin vulnerabilities"""
        if plugin["slug"] == "Unknown":
            return

        try:
            url = f"{self.api_url}/plugins/{plugin['slug']}"
            response = requests.get(
                url,
                headers={"Authorization": f"Token token={self.wpscan_api_key}"},
                timeout=20,
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("vulnerabilities"):
                    for vuln in data["vulnerabilities"]:

                        plugin_version = plugin.get("version")
                        if plugin_version == "Unknown" or self._is_version_vulnerable(
                            plugin_version, vuln
                        ):
                            self.vulnerabilities.append(
                                {
                                    "component_type": "plugin",
                                    "component_name": plugin["name"],
                                    "component_version": plugin["version"],
                                    "severity": vuln.get("severity", "unknown"),
                                    "title": vuln.get("title", "Unknown Vulnerability"),
                                    "description": vuln.get("description", ""),
                                    "fixed_in": vuln.get("fixed_in", ""),
                                    "references": vuln.get("references", {}),
                                }
                            )

        except Exception as e:
            self.logger.error(
                f"Error checking plugin vulnerabilities for {plugin['name']}: {e}"
            )

    def _check_theme_vulnerabilities(self, theme):
        """Check theme vulnerabilities"""
        if theme["slug"] == "Unknown":
            return

        try:
            url = f"{self.api_url}/themes/{theme['slug']}"
            response = requests.get(
                url,
                headers={"Authorization": f"Token token={self.wpscan_api_key}"},
                timeout=20,
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("vulnerabilities"):
                    for vuln in data["vulnerabilities"]:

                        theme_version = theme.get("version")
                        if theme_version == "Unknown" or self._is_version_vulnerable(
                            theme_version, vuln
                        ):
                            self.vulnerabilities.append(
                                {
                                    "component_type": "theme",
                                    "component_name": theme["name"],
                                    "component_version": theme["version"],
                                    "severity": vuln.get("severity", "unknown"),
                                    "title": vuln.get("title", "Unknown Vulnerability"),
                                    "description": vuln.get("description", ""),
                                    "fixed_in": vuln.get("fixed_in", ""),
                                    "references": vuln.get("references", {}),
                                }
                            )

        except Exception as e:
            self.logger.error(
                f"Error checking theme vulnerabilities for {theme['name']}: {e}"
            )

    def _is_version_vulnerable(
        self, current_version: str, vulnerability: Dict[str, Any]
    ) -> bool:
        """Check if the current version is affected by the vulnerability"""

        if not vulnerability.get("fixed_in"):
            return True

        if current_version == "Unknown":
            return True

        try:
            fixed_version = vulnerability.get("fixed_in", "999.999.999")

            current_parts = current_version.split(".")
            fixed_parts = fixed_version.split(".")

            while len(current_parts) < len(fixed_parts):
                current_parts.append("0")
            while len(fixed_parts) < len(current_parts):
                fixed_parts.append("0")

            for current, fixed in zip(current_parts, fixed_parts):

                try:
                    c_val = int(current)
                    f_val = int(fixed)
                    if c_val < f_val:
                        return False
                    if c_val > f_val:
                        return True
                except ValueError:

                    return True

            return False

        except Exception:

            return True
