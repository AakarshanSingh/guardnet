import socket
import urllib.parse
import concurrent.futures
from typing import Dict, Any, List, Optional

from app.scanners.base_scanner import BaseScanner


class PortScanner(BaseScanner):
    """
    Scanner to check for open ports and running services
    """

    name = "Port Scanner"
    description = "Scans for open ports and identifies running services"

    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "Submission (SMTP)",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
    }

    SERVICE_BANNERS = {
        "SSH": b"SSH",
        "FTP": b"220",
        "SMTP": b"220",
        "HTTP": b"HTTP",
        "POP3": b"+OK",
        "IMAP": b"* OK",
        "MySQL": b"\x5b\x00\x00\x00\x0a",
        "RDP": b"\x03\x00\x00",
        "Telnet": b"\xff\xfb",
    }

    def __init__(self, target_url: str, cookies: Optional[str] = None):
        super().__init__(target_url, cookies)
        self.hostname = self._extract_hostname(target_url)
        self.open_ports: List[int] = []
        self.services: Dict[int, str] = {}
        self.port_scan_timeout = 2
        self.max_ports_to_scan = 1000
        self.threads = 50

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(":")[0]

    def scan(self) -> Dict[str, Any]:
        """Run port scan"""
        self.progress = 10

        try:

            self._scan_common_ports()
            self.progress = 50

            self._identify_services()
            self.progress = 90

            dangerous_ports = self._check_dangerous_ports()
            self.progress = 100

            return {
                "hostname": self.hostname,
                "open_ports": self.open_ports,
                "services_detected": self.services,
                "dangerous_ports": dangerous_ports,
            }

        except Exception as e:
            self.logger.error(f"Error in port scan: {e}")
            return {
                "hostname": self.hostname,
                "open_ports": [],
                "services_detected": {},
                "error": str(e),
            }

    def _scan_port(self, port: int) -> bool:
        """
        Scan a single port to check if it's open
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.port_scan_timeout)
                result = s.connect_ex((self.hostname, port))
                return result == 0
        except:
            return False

    def _scan_common_ports(self) -> None:
        """
        Scan commonly used ports
        """

        ports_to_scan = list(self.COMMON_PORTS.keys())

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:

            results = list(executor.map(self._scan_port, ports_to_scan))

            for port, is_open in zip(ports_to_scan, results):
                if is_open:
                    self.open_ports.append(port)
                    self.services[port] = self.COMMON_PORTS.get(port, "Unknown")

    def _get_service_banner(self, port: int) -> Optional[bytes]:
        """
        Try to get service banner from an open port
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.hostname, port))

                banner = s.recv(1024)
                return banner
        except:

            return None

    def _identify_services(self) -> None:
        """
        Try to identify services running on open ports
        """
        for port in self.open_ports:

            if port in self.services and self.services[port] != "Unknown":
                continue

            banner = self._get_service_banner(port)
            if banner:

                for service_name, service_banner in self.SERVICE_BANNERS.items():
                    if service_banner in banner:
                        self.services[port] = service_name
                        break

    def _check_dangerous_ports(self) -> List[Dict[str, Any]]:
        """
        Check for dangerous open ports and services
        """
        dangerous_ports = []

        dangerous_port_info = {
            21: {
                "service": "FTP",
                "reason": "FTP uses clear text authentication and is vulnerable to sniffing attacks",
            },
            23: {
                "service": "Telnet",
                "reason": "Telnet sends data in cleartext and is vulnerable to sniffing attacks",
            },
            135: {
                "service": "MSRPC",
                "reason": "Windows RPC service can be exploited for remote code execution",
            },
            139: {
                "service": "NetBIOS",
                "reason": "NetBIOS can leak system information and has been exploited in the past",
            },
            445: {
                "service": "SMB",
                "reason": "SMB has had critical vulnerabilities like EternalBlue",
            },
            1433: {
                "service": "MSSQL",
                "reason": "SQL Server should not be exposed to the internet",
            },
            1521: {
                "service": "Oracle",
                "reason": "Oracle DB should not be exposed to the internet",
            },
            3306: {
                "service": "MySQL",
                "reason": "MySQL should not be exposed to the internet",
            },
            3389: {
                "service": "RDP",
                "reason": "Remote Desktop has had vulnerabilities and can be brute forced",
            },
            5432: {
                "service": "PostgreSQL",
                "reason": "PostgreSQL should not be exposed to the internet",
            },
            5900: {
                "service": "VNC",
                "reason": "VNC can have weak authentication and should not be publicly accessible",
            },
        }

        for port in self.open_ports:
            if port in dangerous_port_info:
                dangerous_ports.append(
                    {
                        "port": port,
                        "service": self.services.get(
                            port, dangerous_port_info[port]["service"]
                        ),
                        "severity": "high",
                        "reason": dangerous_port_info[port]["reason"],
                    }
                )

        return dangerous_ports
