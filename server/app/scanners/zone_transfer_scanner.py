import urllib.parse
import dns.resolver
import dns.zone
import dns.query
import re
import socket
from typing import Dict, Any, List, Optional

from app.scanners.base_scanner import BaseScanner


class ZoneTransferScanner(BaseScanner):
    """
    Scanner to check for DNS zone transfer vulnerabilities
    """

    name = "Zone Transfer Scanner"
    description = "Checks for DNS zone transfer vulnerabilities"

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.hostname = self._extract_hostname(target_url)
        self.is_ip = self._is_ip_address(self.hostname)

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(":")[0]

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        ip_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
        match = ip_pattern.match(hostname)
        if match:
            for octet in match.groups():
                if int(octet) > 255:
                    return False
            return True
        return False

    def scan(self) -> Dict[str, Any]:
        """Run zone transfer scan"""
        self.progress = 10

        try:
            if self.is_ip:
                self.logger.info(
                    f"Skipping zone transfer scan for IP address: {self.hostname}"
                )
                self.progress = 100
                return {
                    "hostname": self.hostname,
                    "is_ip_address": True,
                    "nameservers": [],
                    "transferable_domains": [],
                    "issues_found": [],
                    "message": "Zone transfer scan skipped for IP addresses",
                }

            nameservers = self._get_nameservers()
            self.progress = 40

            if not nameservers:
                self.logger.info(f"No nameservers found for {self.hostname}")
                self.progress = 100
                return {
                    "hostname": self.hostname,
                    "is_ip_address": False,
                    "nameservers": [],
                    "transferable_domains": [],
                    "issues_found": [],
                    "message": "No nameservers found to test",
                }

            transferable_domains = []
            issues_found = []

            for ns in nameservers:
                try:
                    if self._check_zone_transfer(ns):
                        transferable_domains.append(ns)
                        issues_found.append(
                            {
                                "severity": "high",
                                "title": "Zone Transfer Allowed",
                                "description": f"DNS server {ns} allows zone transfers for {self.hostname}",
                                "nameserver": ns,
                            }
                        )
                except Exception as e:
                    self.logger.warning(
                        f"Error checking zone transfer for nameserver {ns}: {e}"
                    )

            self.progress = 100

            return {
                "hostname": self.hostname,
                "is_ip_address": False,
                "nameservers": nameservers,
                "transferable_domains": transferable_domains,
                "issues_found": issues_found,
            }

        except Exception as e:
            self.logger.error(f"Error in zone transfer scan: {e}")
            return {
                "hostname": self.hostname,
                "is_ip_address": self.is_ip,
                "nameservers": [],
                "transferable_domains": [],
                "issues_found": [
                    {
                        "severity": "unknown",
                        "title": "Zone Transfer Scan Error",
                        "description": f"An error occurred during zone transfer scanning: {str(e)}",
                    }
                ],
            }

    def _get_nameservers(self) -> List[str]:
        """Get nameservers for the domain"""
        try:
            dns.resolver.default_resolver.timeout = 5
            dns.resolver.default_resolver.lifetime = 10

            answers = dns.resolver.resolve(self.hostname, "NS")
            return [rdata.target.to_text().rstrip(".") for rdata in answers]
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain {self.hostname} does not exist")
            return []
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No NS records for {self.hostname}")
            return []
        except dns.resolver.NoNameservers:
            self.logger.warning(f"No nameservers available for {self.hostname}")
            return []
        except dns.exception.Timeout:
            self.logger.warning(f"Timeout resolving NS records for {self.hostname}")
            return []
        except Exception as e:
            self.logger.error(f"Error getting nameservers: {e}")
            return []

    def _check_zone_transfer(self, nameserver: str) -> bool:
        """Check if zone transfer is allowed on a nameserver"""
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(nameserver, self.hostname, timeout=10, lifetime=20)
            )

            self.logger.warning(
                f"Zone transfer allowed on {nameserver} for {self.hostname}"
            )
            return True

        except dns.xfr.TransferError:
            self.logger.info(
                f"Zone transfer not allowed on {nameserver} (transfer error)"
            )
            return False
        except ConnectionRefusedError:
            self.logger.info(f"Connection refused by nameserver {nameserver}")
            return False
        except socket.timeout:
            self.logger.info(f"Timeout connecting to nameserver {nameserver}")
            return False
        except Exception as e:

            self.logger.info(
                f"Zone transfer not allowed on {nameserver} for {self.hostname}: {e}"
            )
            return False
