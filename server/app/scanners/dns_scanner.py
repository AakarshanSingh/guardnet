import dns.resolver
import dns.zone
import dns.query
import urllib.parse
from typing import Dict, Any, List, Optional, Set

from app.scanners.base_scanner import BaseScanner


class DNSScanner(BaseScanner):
    """
    Scanner to check DNS records and configurations
    """

    name = "DNS Scanner"
    description = "Checks DNS records and configurations for security issues"

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.hostname = self._extract_hostname(target_url)

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(":")[0]

    def scan(self) -> Dict[str, Any]:
        """Run DNS scan"""
        self.progress = 10

        try:

            dns_records = self._get_dns_records()
            self.progress = 50

            misconfigurations = self._check_dns_misconfigurations(dns_records)
            self.progress = 90

            self._check_zone_transfers(dns_records)
            self.progress = 100

            return {
                "hostname": self.hostname,
                "records": dns_records,
                "misconfigurations": misconfigurations,
            }

        except Exception as e:
            self.logger.error(f"Error in DNS scan: {e}")
            return {
                "hostname": self.hostname,
                "records": {},
                "misconfigurations": [
                    {
                        "severity": "unknown",
                        "title": "DNS Scan Error",
                        "description": f"An error occurred during DNS scanning: {str(e)}",
                    }
                ],
            }

    def _get_dns_records(self) -> Dict[str, List[str]]:
        """Get various DNS records for the target domain"""
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR"]
        records = {}

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.hostname, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
            ):

                records[record_type] = []
            except Exception as e:
                self.logger.warning(f"Error getting {record_type} records: {e}")
                records[record_type] = []

        try:
            answers = dns.resolver.resolve(self.hostname, "TXT")
            records["SPF"] = [str(rdata) for rdata in answers if "v=spf1" in str(rdata)]
        except Exception:
            records["SPF"] = []

        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.hostname}", "TXT")
            records["DMARC"] = [
                str(rdata) for rdata in answers if "v=DMARC1" in str(rdata)
            ]
        except Exception:
            records["DMARC"] = []

        return records

    def _check_dns_misconfigurations(
        self, dns_records: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for common DNS misconfigurations"""
        misconfigurations = []

        if not dns_records.get("SPF", []):
            misconfigurations.append(
                {
                    "severity": "medium",
                    "title": "Missing SPF Record",
                    "description": "The domain does not have an SPF record, which helps prevent email spoofing.",
                }
            )

        if not dns_records.get("DMARC", []):
            misconfigurations.append(
                {
                    "severity": "medium",
                    "title": "Missing DMARC Record",
                    "description": "The domain does not have a DMARC record, which helps prevent email spoofing and phishing.",
                }
            )

        if not dns_records.get("CAA", []):
            misconfigurations.append(
                {
                    "severity": "low",
                    "title": "Missing CAA Record",
                    "description": "The domain does not have a CAA record, which specifies which certificate authorities are allowed to issue certificates for this domain.",
                }
            )

        try:
            answers = dns.resolver.resolve(self.hostname, "DNSKEY")
            if not answers:
                misconfigurations.append(
                    {
                        "severity": "low",
                        "title": "DNSSec Not Enabled",
                        "description": "The domain does not have DNSSec enabled, which helps prevent DNS spoofing attacks.",
                    }
                )
        except Exception:
            misconfigurations.append(
                {
                    "severity": "low",
                    "title": "DNSSec Not Enabled",
                    "description": "The domain does not have DNSSec enabled, which helps prevent DNS spoofing attacks.",
                }
            )

        ns_records = dns_records.get("NS", [])
        if len(ns_records) < 2:
            misconfigurations.append(
                {
                    "severity": "medium",
                    "title": "Insufficient Nameservers",
                    "description": f"The domain has only {len(ns_records)} nameserver(s). It is recommended to have at least two nameservers for redundancy.",
                }
            )

        ns_ips = set()
        for ns in ns_records:
            try:
                ns = ns.rstrip(".")
                answers = dns.resolver.resolve(ns, "A")
                for rdata in answers:
                    ns_ips.add(str(rdata))
            except Exception:
                pass

        if len(ns_ips) < len(ns_records):
            misconfigurations.append(
                {
                    "severity": "medium",
                    "title": "Nameservers Share IP Addresses",
                    "description": "Some nameservers share IP addresses, which reduces redundancy and creates a single point of failure.",
                }
            )

        return misconfigurations

    def _check_zone_transfers(self, dns_records: Dict[str, List[str]]) -> None:
        """Check if zone transfers are allowed"""
        ns_records = dns_records.get("NS", [])
        zone_transfers = []

        for ns in ns_records:
            try:
                ns = ns.rstrip(".")

                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.hostname, timeout=10))
                if zone:
                    zone_transfers.append(ns)
            except Exception:

                pass

        if zone_transfers:
            dns_records["zone_transfers"] = zone_transfers
            dns_records["zone_transfer_allowed"] = True
