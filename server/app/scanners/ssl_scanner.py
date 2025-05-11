import ssl
import socket
import datetime
from typing import Dict, Any, List, Optional, Tuple
import urllib.parse
import OpenSSL
import requests

from app.scanners.base_scanner import BaseScanner


class SSLScanner(BaseScanner):
    """
    Scanner to check SSL/TLS security
    """

    name = "SSL Scanner"
    description = "Checks for SSL/TLS vulnerabilities and configuration issues"

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.hostname = self._extract_hostname(target_url)
        self.port = 443

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(":")[0]

    def scan(self) -> Dict[str, Any]:
        """Run SSL scan"""
        self.progress = 10

        try:

            cert_details = self._get_certificate_details()
            self.progress = 40

            ssl_issues = self._check_ssl_issues()
            self.progress = 70

            ssl_grade = self._calculate_ssl_grade(cert_details, ssl_issues)
            self.progress = 100

            return {
                "hostname": self.hostname,
                "port": self.port,
                "ssl_grade": ssl_grade,
                "certificate_details": cert_details,
                "issues_found": ssl_issues,
            }

        except Exception as e:
            self.logger.error(f"Error in SSL scan: {e}")
            return {
                "hostname": self.hostname,
                "port": self.port,
                "ssl_grade": "F",
                "certificate_details": {},
                "issues_found": [
                    {
                        "severity": "high",
                        "title": "SSL Connection Error",
                        "description": f"Failed to establish SSL connection: {str(e)}",
                    }
                ],
            }

    def _get_certificate_details(self) -> Dict[str, Any]:
        """Get certificate details from the server"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.hostname, self.port), timeout=10
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1, cert_binary
                    )

                    cert_details = {
                        "subject": {
                            component[0][1]: component[1]
                            for component in cert.get_subject().get_components()
                        },
                        "issuer": {
                            component[0][1]: component[1]
                            for component in cert.get_issuer().get_components()
                        },
                        "version": cert.get_version(),
                        "serial_number": cert.get_serial_number(),
                        "not_before": datetime.datetime.strptime(
                            cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ"
                        ).isoformat(),
                        "not_after": datetime.datetime.strptime(
                            cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"
                        ).isoformat(),
                        "has_expired": cert.has_expired(),
                    }

                    protocols = self._get_supported_protocols()
                    cert_details["supported_protocols"] = protocols

                    cipher_suites = self._get_supported_ciphers()
                    cert_details["cipher_suites"] = cipher_suites

                    return cert_details

        except Exception as e:
            self.logger.error(f"Error getting certificate details: {e}")
            return {}

    def _get_supported_protocols(self) -> Dict[str, bool]:
        """Check which SSL/TLS protocols are supported"""
        protocols = {
            "SSLv2": False,
            "SSLv3": False,
            "TLSv1.0": False,
            "TLSv1.1": False,
            "TLSv1.2": False,
            "TLSv1.3": False,
        }

        for protocol_name, protocol_const in [
            ("SSLv3", ssl.PROTOCOL_SSLv23),
            ("TLSv1.0", ssl.PROTOCOL_TLS),
            ("TLSv1.1", ssl.PROTOCOL_TLS),
            ("TLSv1.2", ssl.PROTOCOL_TLS),
            ("TLSv1.3", ssl.PROTOCOL_TLS),
        ]:
            try:
                context = ssl.SSLContext(protocol_const)
                if protocol_name == "SSLv3":
                    context.options &= ~ssl.OP_NO_SSLv3
                elif protocol_name == "TLSv1.0":
                    context.options &= ~ssl.OP_NO_TLSv1
                elif protocol_name == "TLSv1.1":
                    context.options &= ~ssl.OP_NO_TLSv1_1
                elif protocol_name == "TLSv1.2":
                    context.options &= ~ssl.OP_NO_TLSv1_2
                elif protocol_name == "TLSv1.3":

                    pass

                with socket.create_connection(
                    (self.hostname, self.port), timeout=5
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=self.hostname
                    ) as ssock:
                        protocols[protocol_name] = True
            except:

                pass

        return protocols

    def _get_supported_ciphers(self) -> List[str]:
        """Get supported cipher suites"""
        supported_ciphers = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.hostname, self.port), timeout=5
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher_name = ssock.cipher()[0]
                    supported_ciphers.append(cipher_name)
        except:
            pass

        return supported_ciphers

    def _check_ssl_issues(self) -> List[Dict[str, Any]]:
        """Check for common SSL/TLS security issues"""
        issues = []

        try:

            cert_details = self._get_certificate_details()
            if cert_details.get("has_expired", False):
                issues.append(
                    {
                        "severity": "high",
                        "title": "Certificate Expired",
                        "description": "The SSL/TLS certificate has expired.",
                    }
                )

            if "not_after" in cert_details:
                try:
                    not_after = datetime.datetime.fromisoformat(
                        cert_details["not_after"]
                    )
                    days_to_expiry = (not_after - datetime.datetime.now()).days

                    if 0 < days_to_expiry <= 30:
                        issues.append(
                            {
                                "severity": "medium",
                                "title": "Certificate Expiring Soon",
                                "description": f"The SSL/TLS certificate will expire in {days_to_expiry} days.",
                            }
                        )
                except:
                    pass

            protocols = cert_details.get("supported_protocols", {})

            if protocols.get("SSLv2", False):
                issues.append(
                    {
                        "severity": "high",
                        "title": "SSLv2 Supported",
                        "description": "Server supports SSLv2, which is insecure and deprecated.",
                    }
                )

            if protocols.get("SSLv3", False):
                issues.append(
                    {
                        "severity": "high",
                        "title": "SSLv3 Supported",
                        "description": "Server supports SSLv3, which is vulnerable to the POODLE attack.",
                    }
                )

            if protocols.get("TLSv1.0", False):
                issues.append(
                    {
                        "severity": "medium",
                        "title": "TLSv1.0 Supported",
                        "description": "Server supports TLSv1.0, which is outdated and has known vulnerabilities.",
                    }
                )

            if protocols.get("TLSv1.1", False):
                issues.append(
                    {
                        "severity": "low",
                        "title": "TLSv1.1 Supported",
                        "description": "Server supports TLSv1.1, which is outdated.",
                    }
                )

            if not protocols.get("TLSv1.2", False) and not protocols.get(
                "TLSv1.3", False
            ):
                issues.append(
                    {
                        "severity": "high",
                        "title": "No Modern TLS Support",
                        "description": "Server doesn't support TLSv1.2 or TLSv1.3, which are recommended for secure communication.",
                    }
                )

            try:
                response = requests.get(f"https://{self.hostname}", timeout=10)
                if "strict-transport-security" not in response.headers:
                    issues.append(
                        {
                            "severity": "medium",
                            "title": "HSTS Missing",
                            "description": "HTTP Strict Transport Security (HSTS) header is missing.",
                        }
                    )
            except:
                pass

            return issues
        except Exception as e:
            self.logger.error(f"Error checking SSL issues: {e}")
            return [
                {
                    "severity": "unknown",
                    "title": "SSL Check Error",
                    "description": f"An error occurred while checking SSL issues: {str(e)}",
                }
            ]

    def _calculate_ssl_grade(
        self, cert_details: Dict[str, Any], issues: List[Dict[str, Any]]
    ) -> str:
        """Calculate SSL grade based on issues found"""

        high_count = sum(1 for issue in issues if issue.get("severity") == "high")
        medium_count = sum(1 for issue in issues if issue.get("severity") == "medium")
        low_count = sum(1 for issue in issues if issue.get("severity") == "low")

        if cert_details.get("has_expired", False):
            return "F"

        if high_count > 0:
            return "F" if high_count > 1 else "D"
        elif medium_count > 1:
            return "C"
        elif medium_count == 1 or low_count > 1:
            return "B"
        else:

            protocols = cert_details.get("supported_protocols", {})
            if protocols.get("TLSv1.3", False):
                return "A+"
            elif (
                protocols.get("TLSv1.2", False)
                and not protocols.get("TLSv1.0", False)
                and not protocols.get("TLSv1.1", False)
            ):
                return "A"
            else:
                return "B"
