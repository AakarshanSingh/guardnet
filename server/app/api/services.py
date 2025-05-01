import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.website import Website, WebsiteUrl
from app.models.scan import (
    Scan,
    WPScanResult,
    XSSResult,
    SQLiResult,
    LFIResult,
    CommandInjectionResult,
    SSLResult,
    DNSResult,
    OpenPortsResult,
    ZoneTransferResult,
    DirectoryScanningResult,
)
from app.scanners.wordpress_scanner import WordPressScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.port_scanner import PortScanner
from app.scanners.directory_scanner import DirectoryScanner
from app.scanners.lfi_scanner import LFIScanner
from app.scanners.zone_transfer_scanner import ZoneTransferScanner
from app.scanners.command_injection_scanner import CommandInjectionScanner
from app.scanners.crawl_scanner import VulnerabilityScanCoordinator
from app.utils.browser_manager import browser_manager

logger = logging.getLogger(__name__)


class ScanService:
    """
    Service for managing website scans
    """

    @staticmethod
    async def create_scan_record(
        db: Session, url: str, cookies: Optional[str] = None, user_id: Any = None
    ) -> Scan:
        """
        Create a new scan record without starting the scan
        This separates the database operation from the actual scanning process
        """
        if not user_id:
            raise ValueError("User ID is required")

        # Verify the user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        try:
            # Create a new website entry
            website = Website(user_id=user_id, url=url, cookies=cookies)
            db.add(website)
            db.commit()
            db.refresh(website)

            # Now create a scan for this website
            scan = Scan(website_id=website.id, status="pending")
            db.add(scan)
            db.commit()
            db.refresh(scan)

            return scan
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating scan record: {str(e)}")
            raise ValueError(f"Error creating scan record: {str(e)}")

    @staticmethod
    async def create_scan(
        db: Session, website_id: Any, scan_types: List[str] = None
    ) -> Scan:
        """
        Create a new scan for a website
        """
        # Get website
        website = db.query(Website).filter(Website.id == website_id).first()
        if not website:
            raise ValueError(f"Website with ID {website_id} not found")

        # Create scan record
        scan = Scan(website_id=website_id, status="pending")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Start scan in background
        asyncio.create_task(ScanService.run_scan(db, scan.id, scan_types))

        return scan

    @staticmethod
    async def create_direct_scan(
        db: Session,
        url: str,
        cookies: Optional[str] = None,
        scan_types: List[str] = None,
        user_id: Any = None,
    ) -> Scan:
        """
        Create a new scan directly from a URL without creating a website first
        This is a simplified flow for quick scanning
        """
        if not user_id:
            raise ValueError("User ID is required")

        # Verify the user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        try:
            # Create a new website entry - UUID handling is now managed by the model
            website = Website(user_id=user_id, url=url, cookies=cookies)
            db.add(website)
            db.commit()
            db.refresh(website)

            # Now create a scan for this website
            scan = Scan(website_id=website.id, status="pending")
            db.add(scan)
            db.commit()
            db.refresh(scan)

            # Start scan in background
            asyncio.create_task(ScanService.run_scan(db, scan.id, scan_types))

            return scan
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating direct scan: {str(e)}")
            raise ValueError(f"Error creating scan: {str(e)}")

    @staticmethod
    def run_scan(db: Session, scan_id: Any, scan_types: List[str] = None) -> None:
        """
        Run a scan in the background
        This method is designed to be called from FastAPI's BackgroundTasks
        or directly, but should not be awaited when used with BackgroundTasks
        """
        # Default scan types if none provided
        if not scan_types:
            scan_types = [
                "wordpress",
                "ssl",
                "dns",
                "ports",
                "directory",
                "lfi",
                "zone_transfer",
                "command_injection",
                "xss",
                "sqli",
            ]

        try:
            # Get scan
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan with ID {scan_id} not found")
                return

            # Update scan status
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            db.commit()

            # Get website
            website = db.query(Website).filter(Website.id == scan.website_id).first()
            if not website:
                logger.error(f"Website with ID {scan.website_id} not found")
                scan.status = "failed"
                db.commit()
                return

            # Run each scanner - we can't use await here because this function is meant to run in a background task
            current_scanner = "initializing"

            try:
                # Identify which scan types need crawling
                needs_crawling = any(
                    scan_type in scan_types for scan_type in ["xss", "sqli", "lfi"]
                )

                # MODIFIED SCAN ORDER: Run non-crawler scanners first, then run crawler-based scanners last

                # 1. WordPress scan
                if "wordpress" in scan_types:
                    current_scanner = "wordpress"
                    scanner = WordPressScanner(website.url, website.cookies)
                    results = scanner.run()

                    if results.get("is_wordpress"):
                        # Save WordPress scan results
                        wp_result = WPScanResult(
                            scan_id=scan.id,
                            vulnerabilities_found=json.dumps(
                                results.get("vulnerabilities", [])
                            ),
                            plugins_found=json.dumps(results.get("plugins", [])),
                            themes_found=json.dumps(results.get("themes", [])),
                            version_info=results.get("version"),
                        )
                        db.add(wp_result)
                        db.commit()

                # 2. Command Injection scan
                if "command_injection" in scan_types:
                    current_scanner = "command_injection"
                    scanner = CommandInjectionScanner(website.url, website.cookies)
                    results = scanner.run()

                    # Save Command Injection scan results
                    cmd_injection_result = CommandInjectionResult(
                        scan_id=scan.id,
                        vulnerable_endpoints=json.dumps(
                            results.get("vulnerable_endpoints", [])
                        ),
                        commands_executed=json.dumps(
                            [
                                payload["payload"]
                                for payload in results.get("vulnerable_endpoints", [])
                            ]
                        ),
                    )
                    db.add(cmd_injection_result)
                    db.commit()

                # 3. SSL scan
                if "ssl" in scan_types:
                    current_scanner = "ssl"
                    if website.url.startswith("https://"):
                        scanner = SSLScanner(website.url, website.cookies)
                        results = scanner.run()

                        # Save SSL scan results
                        ssl_result = SSLResult(
                            scan_id=scan.id,
                            ssl_grade=results.get("ssl_grade"),
                            issues_found=json.dumps(results.get("issues_found", [])),
                            certificate_details=json.dumps(
                                results.get("certificate_details", {})
                            ),
                        )
                        db.add(ssl_result)
                        db.commit()

                # 4. DNS scan
                if "dns" in scan_types:
                    current_scanner = "dns"
                    scanner = DNSScanner(website.url, website.cookies)
                    results = scanner.run()

                    # Save DNS scan results
                    dns_result = DNSResult(
                        scan_id=scan.id,
                        records=json.dumps(results.get("records", {})),
                        misconfigurations=json.dumps(
                            results.get("misconfigurations", [])
                        ),
                    )
                    db.add(dns_result)
                    db.commit()

                # 5. Port scan
                if "ports" in scan_types:
                    current_scanner = "ports"
                    scanner = PortScanner(website.url, website.cookies)
                    results = scanner.run()

                    # Save port scan results
                    port_result = OpenPortsResult(
                        scan_id=scan.id,
                        open_ports=json.dumps(results.get("open_ports", [])),
                        services_detected=json.dumps(
                            results.get("services_detected", {})
                        ),
                    )
                    db.add(port_result)
                    db.commit()

                # 6. Zone Transfer scan
                if "zone_transfer" in scan_types:
                    current_scanner = "zone_transfer"
                    scanner = ZoneTransferScanner(website.url, website.cookies)
                    results = scanner.run()

                    # Save Zone Transfer scan results
                    zone_transfer_result = ZoneTransferResult(
                        scan_id=scan.id,
                        transferable_domains=json.dumps(
                            results.get("transferable_domains", [])
                        ),
                        issues_found=json.dumps(results.get("issues_found", [])),
                    )
                    db.add(zone_transfer_result)
                    db.commit()

                # 7. Directory scan
                if "directory" in scan_types:
                    current_scanner = "directory"
                    scanner = DirectoryScanner(website.url, website.cookies)
                    results = scanner.run()

                    # Save directory scan results
                    dir_result = DirectoryScanningResult(
                        scan_id=scan.id,
                        directories_found=json.dumps(
                            results.get("directories_found", [])
                        ),
                        sensitive_files_found=json.dumps(
                            results.get("sensitive_files_found", [])
                        ),
                    )
                    db.add(dir_result)
                    db.commit()

                # 8. Run crawler-based scanners LAST if they're requested
                if needs_crawling:
                    current_scanner = "advanced_scanners"
                    try:
                        # Launch a coordinator that handles crawling and running these scanners
                        ScanService._run_advanced_scanners(
                            db, scan, website, scan_types
                        )
                    except Exception as e:
                        logger.error(f"Error in advanced scanners: {str(e)}")
                        # Continue with the scan even if advanced scanners fail
                        # This ensures other results are still saved

                # Update scan status on completion
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                db.commit()

            except Exception as e:
                logger.error(
                    f"Error in {current_scanner} scan for scan ID {scan_id}: {str(e)}"
                )
                scan.status = "failed"
                db.commit()

        except Exception as e:
            logger.error(f"Error running scan {scan_id}: {str(e)}")
            try:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = "failed"
                    db.commit()
            except Exception:
                pass

    @staticmethod
    def _run_advanced_scanners(
        db: Session, scan: Scan, website: Website, scan_types: List[str]
    ) -> None:
        """
        Run advanced scanners that require JavaScript rendering and browser automation.
        This includes XSS, SQLi, and LFI which need a crawler to find injectable points.

        Args:
            db: Database session
            scan: Scan object
            website: Website object
            scan_types: List of scan types to run
        """
        try:
            logger.info(
                f"Starting advanced vulnerability scan for website {website.url}"
            )

            # Create and run the vulnerability scan coordinator in a new thread
            loop = asyncio.new_event_loop()

            # Run the coordinator in a separate thread to avoid blocking
            def run_coordinator():
                asyncio.set_event_loop(loop)
                coordinator = VulnerabilityScanCoordinator(db, scan.id, website)
                loop.run_until_complete(coordinator.run_scan())

            import threading

            coordinator_thread = threading.Thread(target=run_coordinator)
            coordinator_thread.daemon = True
            coordinator_thread.start()

            # Wait for the coordinator to complete or timeout after 15 minutes
            coordinator_thread.join(timeout=900)

            if coordinator_thread.is_alive():
                logger.warning(
                    f"Advanced vulnerability scan for {website.url} is taking too long, continuing with next scans"
                )

            logger.info(
                f"Completed advanced vulnerability scan for website {website.url}"
            )

        except Exception as e:
            logger.error(
                f"Error running advanced vulnerability scan: {str(e)}", exc_info=True
            )

    @staticmethod
    def stop_scan(db: Session, scan_id: Any, user_id: Any) -> Dict[str, Any]:
        """
        Stop a running scan

        Args:
            db: Database session
            scan_id: ID of the scan to stop
            user_id: ID of the user requesting to stop the scan

        Returns:
            Dict with scan details and success status
        """

        # Check if scan exists and belongs to the user
        scan = (
            db.query(Scan)
            .join(Website)
            .filter(Scan.id == scan_id, Website.user_id == user_id)
            .first()
        )

        if not scan:
            raise ValueError(
                f"Scan with ID {scan_id} not found or does not belong to user"
            )

        # Only stop if the scan is running or pending
        if scan.status not in ["running", "pending"]:
            return {
                "id": scan.id,
                "status": scan.status,
                "message": f"Scan is already in status: {scan.status}, cannot stop",
                "success": False,
            }

        # Only close the browser instance if WordPress scanning is involved
        # as other scanners use direct HTTP requests, not browser automation
        try:
            # Get scan types from the original scan request if available
            # For now assume WordPress scan is included in default scans
            logger.info(f"Closing browser instance for scan {scan_id}")
            browser_manager.close_browser()
        except Exception as e:
            logger.error(f"Error closing browser instance: {e}")

        # Update scan status to stopped
        scan.status = "stopped"
        scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)

        return {
            "id": scan.id,
            "status": scan.status,
            "message": "Scan stopped successfully",
            "success": True,
        }

    @staticmethod
    async def _run_wordpress_scan(db: Session, scan: Scan, website: Website) -> None:
        """Run WordPress scan"""
        scanner = WordPressScanner(website.url, website.cookies)
        results = scanner.run()

        if results.get("is_wordpress"):
            # Save WordPress scan results
            wp_result = WPScanResult(
                scan_id=scan.id,
                vulnerabilities_found=json.dumps(results.get("vulnerabilities", [])),
                plugins_found=json.dumps(results.get("plugins", [])),
                themes_found=json.dumps(results.get("themes", [])),
                version_info=results.get("version"),
            )
            db.add(wp_result)
            db.commit()

    @staticmethod
    async def _run_ssl_scan(db: Session, scan: Scan, website: Website) -> None:
        """Run SSL scan"""
        if not website.url.startswith("https://"):
            # Skip SSL scan for non-HTTPS sites
            return

        scanner = SSLScanner(website.url, website.cookies)
        results = scanner.run()

        # Save SSL scan results
        ssl_result = SSLResult(
            scan_id=scan.id,
            ssl_grade=results.get("ssl_grade"),
            issues_found=json.dumps(results.get("issues_found", [])),
            certificate_details=json.dumps(results.get("certificate_details", {})),
        )
        db.add(ssl_result)
        db.commit()

    @staticmethod
    async def _run_dns_scan(db: Session, scan: Scan, website: Website) -> None:
        """Run DNS scan"""
        scanner = DNSScanner(website.url, website.cookies)
        results = scanner.run()

        # Save DNS scan results
        dns_result = DNSResult(
            scan_id=scan.id,
            records=json.dumps(results.get("records", {})),
            misconfigurations=json.dumps(results.get("misconfigurations", [])),
        )
        db.add(dns_result)
        db.commit()

    @staticmethod
    async def _run_port_scan(db: Session, scan: Scan, website: Website) -> None:
        """Run port scan"""
        scanner = PortScanner(website.url, website.cookies)
        results = scanner.run()

        # Save port scan results
        port_result = OpenPortsResult(
            scan_id=scan.id,
            open_ports=json.dumps(results.get("open_ports", [])),
            services_detected=json.dumps(results.get("services_detected", {})),
        )
        db.add(port_result)
        db.commit()

    @staticmethod
    async def _run_directory_scan(db: Session, scan: Scan, website: Website) -> None:
        """Run directory scan"""
        scanner = DirectoryScanner(website.url, website.cookies)
        results = scanner.run()

        # Save directory scan results
        dir_result = DirectoryScanningResult(
            scan_id=scan.id,
            directories_found=json.dumps(results.get("directories_found", [])),
            sensitive_files_found=json.dumps(results.get("sensitive_files_found", [])),
        )
        db.add(dir_result)
        db.commit()

    @staticmethod
    async def _run_lfi_scan(db: Session, scan: Scan, website: Website) -> None:
        """Run LFI scan"""
        scanner = LFIScanner(website.url, website.cookies)
        results = scanner.run()

        # Save LFI scan results
        lfi_result = LFIResult(
            scan_id=scan.id,
            vulnerable_endpoints=json.dumps(results.get("vulnerable_endpoints", [])),
        )
        db.add(lfi_result)
        db.commit()

    @staticmethod
    async def _run_zone_transfer_scan(
        db: Session, scan: Scan, website: Website
    ) -> None:
        """Run Zone Transfer scan"""
        scanner = ZoneTransferScanner(website.url, website.cookies)
        results = scanner.run()

        # Save Zone Transfer scan results
        zone_transfer_result = ZoneTransferResult(
            scan_id=scan.id,
            transferable_domains=json.dumps(results.get("transferable_domains", [])),
            issues_found=json.dumps(results.get("issues_found", [])),
        )
        db.add(zone_transfer_result)
        db.commit()

    @staticmethod
    async def _run_command_injection_scan(
        db: Session, scan: Scan, website: Website
    ) -> None:
        """Run Command Injection scan"""
        scanner = CommandInjectionScanner(website.url, website.cookies)
        results = scanner.run()

        # Save Command Injection scan results
        cmd_injection_result = CommandInjectionResult(
            scan_id=scan.id,
            vulnerable_endpoints=json.dumps(results.get("vulnerable_endpoints", [])),
            commands_executed=json.dumps(
                [
                    payload["payload"]
                    for payload in results.get("vulnerable_endpoints", [])
                ]
            ),
        )
        db.add(cmd_injection_result)
        db.commit()

    @staticmethod
    def get_scan_status(db: Session, scan_id: Any) -> Dict[str, Any]:
        """
        Get the status of a scan
        """
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found")

        return {
            "id": scan.id,
            "website_id": scan.website_id,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "created_at": scan.created_at,
        }

    @staticmethod
    def get_scan_result(db: Session, scan_id: Any) -> Dict[str, Any]:
        """
        Get the comprehensive result of a scan, including all related data from all scanner tables
        """
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found")

        # Base result with scan metadata
        result = {
            "scan": {
                "id": scan.id,
                "website_id": scan.website_id,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "created_at": scan.created_at,
            },
            "website": {"id": scan.website.id, "url": scan.website.url},
        }

        # 1. WordPress scan results
        wp_result = (
            db.query(WPScanResult).filter(WPScanResult.scan_id == scan_id).first()
        )
        if wp_result:
            result["wordpress"] = {
                "is_wordpress": True,
                "version": wp_result.version_info,
                "plugins": (
                    json.loads(wp_result.plugins_found)
                    if wp_result.plugins_found
                    else []
                ),
                "themes": (
                    json.loads(wp_result.themes_found) if wp_result.themes_found else []
                ),
                "vulnerabilities": (
                    json.loads(wp_result.vulnerabilities_found)
                    if wp_result.vulnerabilities_found
                    else []
                ),
            }
        else:
            result["wordpress"] = {"is_wordpress": False}

        # 2. SSL scan results
        ssl_result = db.query(SSLResult).filter(SSLResult.scan_id == scan_id).first()
        if ssl_result:
            result["ssl"] = {
                "ssl_grade": ssl_result.ssl_grade,
                "issues_found": (
                    json.loads(ssl_result.issues_found)
                    if ssl_result.issues_found
                    else []
                ),
                "certificate_details": (
                    json.loads(ssl_result.certificate_details)
                    if ssl_result.certificate_details
                    else {}
                ),
            }

        # 3. DNS scan results
        dns_result = db.query(DNSResult).filter(DNSResult.scan_id == scan_id).first()
        if dns_result:
            result["dns"] = {
                "records": json.loads(dns_result.records) if dns_result.records else {},
                "misconfigurations": (
                    json.loads(dns_result.misconfigurations)
                    if dns_result.misconfigurations
                    else []
                ),
            }

        # 4. Port scan results
        port_result = (
            db.query(OpenPortsResult).filter(OpenPortsResult.scan_id == scan_id).first()
        )
        if port_result:
            result["ports"] = {
                "open_ports": (
                    json.loads(port_result.open_ports) if port_result.open_ports else []
                ),
                "services_detected": (
                    json.loads(port_result.services_detected)
                    if port_result.services_detected
                    else {}
                ),
            }

        # 5. Directory scan results
        dir_result = (
            db.query(DirectoryScanningResult)
            .filter(DirectoryScanningResult.scan_id == scan_id)
            .first()
        )
        if dir_result:
            result["directories"] = {
                "directories_found": (
                    json.loads(dir_result.directories_found)
                    if dir_result.directories_found
                    else []
                ),
                "sensitive_files_found": (
                    json.loads(dir_result.sensitive_files_found)
                    if dir_result.sensitive_files_found
                    else []
                ),
            }

        # 6. LFI scan results
        lfi_result = db.query(LFIResult).filter(LFIResult.scan_id == scan_id).first()
        if lfi_result:
            result["lfi"] = {
                "vulnerable_endpoints": (
                    json.loads(lfi_result.vulnerable_endpoints)
                    if lfi_result.vulnerable_endpoints
                    else []
                ),
            }

        # 7. Command Injection scan results
        cmd_injection_result = (
            db.query(CommandInjectionResult)
            .filter(CommandInjectionResult.scan_id == scan_id)
            .first()
        )
        if cmd_injection_result:
            result["command_injection"] = {
                "vulnerable_endpoints": (
                    json.loads(cmd_injection_result.vulnerable_endpoints)
                    if cmd_injection_result.vulnerable_endpoints
                    else []
                ),
            }

        # 8. Zone Transfer scan results
        zone_transfer_result = (
            db.query(ZoneTransferResult)
            .filter(ZoneTransferResult.scan_id == scan_id)
            .first()
        )
        if zone_transfer_result:
            result["zone_transfer"] = {
                "transferable_domains": (
                    json.loads(zone_transfer_result.transferable_domains)
                    if zone_transfer_result.transferable_domains
                    else []
                ),
                "issues_found": (
                    json.loads(zone_transfer_result.issues_found)
                    if zone_transfer_result.issues_found
                    else []
                ),
            }

        # 9. SQLi and XSS results (these are linked to website_url, not directly to scan)
        # First get all website_url_ids associated with this website
        website_urls = (
            db.query(WebsiteUrl).filter(WebsiteUrl.website_id == scan.website_id).all()
        )
        website_url_ids = [url.id for url in website_urls]

        if website_url_ids:
            # XSS results
            xss_results = (
                db.query(XSSResult)
                .filter(XSSResult.website_url_id.in_(website_url_ids))
                .all()
            )
            if xss_results:
                result["xss"] = []
                for xss_result in xss_results:
                    result["xss"].append(
                        {
                            "website_url_id": xss_result.website_url_id,
                            "vulnerable_endpoints": (
                                json.loads(xss_result.vulnerable_endpoints)
                                if xss_result.vulnerable_endpoints
                                else []
                            ),
                        }
                    )

            # SQLi results
            sqli_results = (
                db.query(SQLiResult)
                .filter(SQLiResult.website_url_id.in_(website_url_ids))
                .all()
            )
            if sqli_results:
                result["sqli"] = []
                for sqli_result in sqli_results:
                    result["sqli"].append(
                        {
                            "website_url_id": sqli_result.website_url_id,
                            "vulnerable_params": (
                                json.loads(sqli_result.vulnerable_params)
                                if sqli_result.vulnerable_params
                                else []
                            ),
                            "dbms_info": sqli_result.dbms_info,
                        }
                    )

        # Convert any UUIDs to strings before returning
        return ScanService.convert_uuid_to_str(result)

    @staticmethod
    def list_scans(
        db: Session, user_id: Any, page: int = 1, page_size: int = 10
    ) -> Dict[str, Any]:
        """
        List scans for a user with pagination
        """
        # Get total count
        total = db.query(Scan).join(Website).filter(Website.user_id == user_id).count()

        # Calculate pages
        pages = (total + page_size - 1) // page_size

        # Get scans
        scans = (
            db.query(Scan)
            .join(Website)
            .filter(Website.user_id == user_id)
            .order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "items": scans,
        }

    @staticmethod
    def generate_report(db: Session, scan_id: Any, report_format: str = "json") -> Any:
        """
        Generate a report for a scan in various formats

        Returns:
            Dict for JSON format, FastAPI Response objects for other formats
        """
        from fastapi.responses import Response
        import pandas as pd
        import io
        import urllib.parse

        # Get scan result
        scan_result = ScanService.get_scan_result(db, scan_id)

        # Get scan info for filename
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found")

        # Extract domain from URL for filename
        website = db.query(Website).filter(Website.id == scan.website_id).first()
        parsed_url = urllib.parse.urlparse(website.url)
        domain = parsed_url.netloc.replace(":", "_").replace(".", "_")
        timestamp = scan.created_at.strftime("%Y%m%d_%H%M%S")
        filename_base = f"security_scan_{domain}_{timestamp}"

        # Format and return based on requested format
        report_format = report_format.lower()

        if report_format == "json":
            return scan_result

        elif report_format == "excel":
            try:
                # Convert to Excel format
                output = io.BytesIO()

                # Create a pandas Excel writer
                with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                    # Create worksheets for each scan type

                    # Overview sheet
                    overview_data = {
                        "Property": [
                            "URL",
                            "Scan Date",
                            "Status",
                            "Start Time",
                            "End Time",
                        ],
                        "Value": [
                            website.url,
                            scan.created_at.strftime("%Y-%m-%d"),
                            scan.status,
                            (
                                scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
                                if scan.started_at
                                else "N/A"
                            ),
                            (
                                scan.completed_at.strftime("%Y-%m-%d %H:%M:%S")
                                if scan.completed_at
                                else "N/A"
                            ),
                        ],
                    }
                    pd.DataFrame(overview_data).to_excel(
                        writer, sheet_name="Overview", index=False
                    )

                    # Handle each scan result section
                    if "wordpress" in scan_result and scan_result["wordpress"].get(
                        "is_wordpress"
                    ):
                        # WordPress vulnerabilities
                        if scan_result["wordpress"].get("vulnerabilities"):
                            vulns = scan_result["wordpress"]["vulnerabilities"]
                            if vulns:
                                df = pd.json_normalize(vulns)
                                df.to_excel(
                                    writer, sheet_name="WordPress Vulns", index=False
                                )

                    # SSL issues
                    if "ssl" in scan_result and scan_result["ssl"].get("issues_found"):
                        issues = scan_result["ssl"]["issues_found"]
                        if issues:
                            df = pd.json_normalize(issues)
                            df.to_excel(writer, sheet_name="SSL Issues", index=False)

                    # DNS misconfigurations
                    if "dns" in scan_result and scan_result["dns"].get(
                        "misconfigurations"
                    ):
                        issues = scan_result["dns"]["misconfigurations"]
                        if issues:
                            df = pd.json_normalize(issues)
                            df.to_excel(writer, sheet_name="DNS Issues", index=False)

                    # Port scan results
                    if "ports" in scan_result and scan_result["ports"].get(
                        "open_ports"
                    ):
                        ports = scan_result["ports"]["open_ports"]
                        services = scan_result["ports"].get("services_detected", {})
                        if ports:
                            port_data = []
                            for port in ports:
                                service = services.get(str(port), "Unknown")
                                port_data.append({"port": port, "service": service})
                            pd.DataFrame(port_data).to_excel(
                                writer, sheet_name="Open Ports", index=False
                            )

                    # LFI vulnerabilities
                    if "lfi" in scan_result and scan_result["lfi"].get(
                        "vulnerable_endpoints"
                    ):
                        vulns = scan_result["lfi"]["vulnerable_endpoints"]
                        if vulns:
                            df = pd.json_normalize(vulns)
                            df.to_excel(writer, sheet_name="LFI Vulns", index=False)

                # Reset the buffer position to the beginning
                output.seek(0)

                # Create response with Excel file
                filename = f"{filename_base}.xlsx"
                media_type = (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
                headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

                return Response(
                    content=output.getvalue(), media_type=media_type, headers=headers
                )
            except Exception as e:
                logger.error(f"Error generating Excel report: {e}")
                raise ValueError(f"Error generating Excel report: {str(e)}")

        elif report_format == "pdf":
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import (
                    SimpleDocTemplate,
                    Paragraph,
                    Spacer,
                    Table,
                    TableStyle,
                )
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib import colors
                from reportlab.lib.enums import TA_LEFT

                # Create a buffer for the PDF
                buffer = io.BytesIO()

                # Set up page size with margins
                page_width, page_height = letter
                margin = 36  # 0.5 inch margins
                effective_width = page_width - (2 * margin)

                # Create the PDF document with proper margins
                doc = SimpleDocTemplate(
                    buffer,
                    pagesize=letter,
                    leftMargin=margin,
                    rightMargin=margin,
                    topMargin=margin,
                    bottomMargin=margin,
                )

                # Create styles for the document
                styles = getSampleStyleSheet()
                title_style = styles["Heading1"]
                heading2_style = styles["Heading2"]
                normal_style = styles["Normal"]

                # Create a custom style for table cells with word wrapping
                table_cell_style = ParagraphStyle(
                    "TableCell",
                    parent=normal_style,
                    fontSize=8,
                    leading=10,
                    wordWrap="CJK",
                    alignment=TA_LEFT,
                )

                # Helper function to create wrapped paragraphs for table cells
                def wrap_text(text):
                    if not text:
                        return Paragraph("Unknown", table_cell_style)
                    return Paragraph(str(text), table_cell_style)

                # Build story (content)
                story = []

                # Title
                story.append(
                    Paragraph(f"Security Scan Report: {website.url}", title_style)
                )
                story.append(Spacer(1, 12))

                # Overview section
                story.append(Paragraph("Scan Overview", heading2_style))
                story.append(Spacer(1, 6))

                overview_data = [
                    ["URL", wrap_text(website.url)],
                    ["Scan Date", wrap_text(scan.created_at.strftime("%Y-%m-%d"))],
                    ["Status", wrap_text(scan.status)],
                    [
                        "Start Time",
                        wrap_text(
                            scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
                            if scan.started_at
                            else "N/A"
                        ),
                    ],
                    [
                        "End Time",
                        wrap_text(
                            scan.completed_at.strftime("%Y-%m-%d %H:%M:%S")
                            if scan.completed_at
                            else "N/A"
                        ),
                    ],
                ]

                overview_table = Table(
                    overview_data, colWidths=[100, effective_width - 100]
                )
                overview_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                story.append(overview_table)
                story.append(Spacer(1, 12))

                # 1. WordPress scan results
                if "wordpress" in scan_result:
                    story.append(Paragraph("WordPress Scan Results", heading2_style))
                    story.append(Spacer(1, 6))

                    if scan_result["wordpress"].get("is_wordpress"):
                        story.append(
                            Paragraph(
                                f"WordPress Version: {scan_result['wordpress'].get('version', 'Unknown')}",
                                normal_style,
                            )
                        )

                        # Add plugins if any
                        plugins = scan_result["wordpress"].get("plugins", [])
                        if plugins:
                            story.append(Spacer(1, 6))
                            story.append(
                                Paragraph("WordPress Plugins", styles["Heading3"])
                            )

                            plugin_data = [["Name", "Version", "URL"]]
                            for plugin in plugins:
                                plugin_data.append(
                                    [
                                        wrap_text(plugin.get("name", "Unknown")),
                                        wrap_text(plugin.get("version", "Unknown")),
                                        wrap_text(plugin.get("url", "Unknown")),
                                    ]
                                )

                            plugin_table = Table(
                                plugin_data, colWidths=[120, 80, effective_width - 200]
                            )
                            plugin_table.setStyle(
                                TableStyle(
                                    [
                                        (
                                            "BACKGROUND",
                                            (0, 0),
                                            (-1, 0),
                                            colors.lightgrey,
                                        ),
                                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ]
                                )
                            )
                            story.append(plugin_table)

                        # Add themes if any
                        themes = scan_result["wordpress"].get("themes", [])
                        if themes:
                            story.append(Spacer(1, 6))
                            story.append(
                                Paragraph("WordPress Themes", styles["Heading3"])
                            )

                            theme_data = [["Name", "Version", "URL"]]
                            for theme in themes:
                                theme_data.append(
                                    [
                                        wrap_text(theme.get("name", "Unknown")),
                                        wrap_text(theme.get("version", "Unknown")),
                                        wrap_text(theme.get("url", "Unknown")),
                                    ]
                                )

                            theme_table = Table(
                                theme_data, colWidths=[120, 80, effective_width - 200]
                            )
                            theme_table.setStyle(
                                TableStyle(
                                    [
                                        (
                                            "BACKGROUND",
                                            (0, 0),
                                            (-1, 0),
                                            colors.lightgrey,
                                        ),
                                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ]
                                )
                            )
                            story.append(theme_table)

                        # Add vulnerabilities if any
                        vulnerabilities = scan_result["wordpress"].get(
                            "vulnerabilities", []
                        )
                        if vulnerabilities:
                            story.append(Spacer(1, 6))
                            story.append(
                                Paragraph(
                                    "WordPress Vulnerabilities", styles["Heading3"]
                                )
                            )

                            vuln_data = [["Component", "Version", "Title", "Severity"]]
                            for vuln in vulnerabilities:
                                vuln_data.append(
                                    [
                                        wrap_text(
                                            vuln.get("component_name", "Unknown")
                                        ),
                                        wrap_text(
                                            vuln.get("component_version", "Unknown")
                                        ),
                                        wrap_text(vuln.get("title", "Unknown")),
                                        wrap_text(vuln.get("severity", "Unknown")),
                                    ]
                                )

                            col_widths = [100, 70, effective_width - 250, 80]
                            vuln_table = Table(vuln_data, colWidths=col_widths)
                            vuln_table.setStyle(
                                TableStyle(
                                    [
                                        (
                                            "BACKGROUND",
                                            (0, 0),
                                            (-1, 0),
                                            colors.lightgrey,
                                        ),
                                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ]
                                )
                            )
                            story.append(vuln_table)
                    else:
                        story.append(Paragraph("Not a WordPress website", normal_style))

                    story.append(Spacer(1, 12))

                # 2. SSL section
                if "ssl" in scan_result:
                    story.append(Paragraph("SSL Scan Results", heading2_style))
                    story.append(Spacer(1, 6))

                    story.append(
                        Paragraph(
                            f"SSL Grade: {scan_result['ssl'].get('ssl_grade', 'Unknown')}",
                            normal_style,
                        )
                    )

                    # Certificate details
                    cert_details = scan_result["ssl"].get("certificate_details", {})
                    if cert_details:
                        story.append(Spacer(1, 6))
                        story.append(
                            Paragraph("Certificate Details", styles["Heading3"])
                        )
                        cert_data = []
                        for key, value in cert_details.items():
                            if isinstance(value, (dict, list)):
                                value = str(value)
                            cert_data.append([wrap_text(key), wrap_text(value)])

                        if cert_data:
                            cert_table = Table(
                                cert_data, colWidths=[150, effective_width - 150]
                            )
                            cert_table.setStyle(
                                TableStyle(
                                    [
                                        (
                                            "BACKGROUND",
                                            (0, 0),
                                            (0, -1),
                                            colors.lightgrey,
                                        ),
                                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ]
                                )
                            )
                            story.append(cert_table)

                    # SSL issues
                    issues = scan_result["ssl"].get("issues_found", [])
                    if issues:
                        story.append(Spacer(1, 6))
                        story.append(Paragraph("SSL Issues", styles["Heading3"]))

                        issue_data = [["Issue", "Severity"]]
                        for issue in issues:
                            issue_data.append(
                                [
                                    wrap_text(issue.get("title", "Unknown")),
                                    wrap_text(issue.get("severity", "Unknown")),
                                ]
                            )

                        issue_table = Table(
                            issue_data, colWidths=[effective_width - 100, 100]
                        )
                        issue_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(issue_table)

                    story.append(Spacer(1, 12))

                # 3. DNS section
                if "dns" in scan_result:
                    story.append(Paragraph("DNS Scan Results", heading2_style))
                    story.append(Spacer(1, 6))

                    # DNS Records
                    records = scan_result["dns"].get("records", {})
                    if records:
                        story.append(Paragraph("DNS Records", styles["Heading3"]))
                        story.append(Spacer(1, 6))

                        for record_type, values in records.items():
                            story.append(
                                Paragraph(f"{record_type} Records:", styles["Heading4"])
                            )
                            if isinstance(values, list) and values:
                                record_data = [[f"{record_type} Value"]]
                                for value in values:
                                    record_data.append([wrap_text(value)])

                                record_table = Table(
                                    record_data, colWidths=[effective_width]
                                )
                                record_table.setStyle(
                                    TableStyle(
                                        [
                                            (
                                                "BACKGROUND",
                                                (0, 0),
                                                (-1, 0),
                                                colors.lightgrey,
                                            ),
                                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                        ]
                                    )
                                )
                                story.append(record_table)
                                story.append(Spacer(1, 6))

                    # DNS Misconfigurations
                    misconfigurations = scan_result["dns"].get("misconfigurations", [])
                    if misconfigurations:
                        story.append(
                            Paragraph("DNS Misconfigurations", styles["Heading3"])
                        )
                        story.append(Spacer(1, 6))

                        miscfg_data = [["Issue", "Severity", "Description"]]
                        for issue in misconfigurations:
                            miscfg_data.append(
                                [
                                    wrap_text(issue.get("title", "Unknown")),
                                    wrap_text(issue.get("severity", "Unknown")),
                                    wrap_text(issue.get("description", "Unknown")),
                                ]
                            )

                        miscfg_table = Table(
                            miscfg_data, colWidths=[100, 70, effective_width - 170]
                        )
                        miscfg_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(miscfg_table)

                    story.append(Spacer(1, 12))

                # 4. Port scan results
                if "ports" in scan_result:
                    story.append(Paragraph("Open Ports Scan Results", heading2_style))
                    story.append(Spacer(1, 6))

                    ports = scan_result["ports"].get("open_ports", [])
                    services = scan_result["ports"].get("services_detected", {})

                    if ports:
                        port_data = [["Port", "Service"]]
                        for port in ports:
                            service = services.get(str(port), "Unknown")
                            port_data.append([wrap_text(str(port)), wrap_text(service)])

                        port_table = Table(
                            port_data, colWidths=[80, effective_width - 80]
                        )
                        port_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(port_table)
                    else:
                        story.append(Paragraph("No open ports detected", normal_style))

                    story.append(Spacer(1, 12))

                # 5. Directory scanning results
                if "directories" in scan_result:
                    story.append(
                        Paragraph("Directory Scanning Results", heading2_style)
                    )
                    story.append(Spacer(1, 6))

                    # Directories found
                    directories = scan_result["directories"].get(
                        "directories_found", []
                    )
                    if directories:
                        story.append(Paragraph("Directories Found", styles["Heading3"]))
                        story.append(Spacer(1, 6))

                        dir_data = [["Directory Path"]]
                        for directory in directories:
                            dir_data.append([wrap_text(directory)])

                        dir_table = Table(dir_data, colWidths=[effective_width])
                        dir_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(dir_table)
                        story.append(Spacer(1, 6))

                    # Sensitive files found
                    sensitive_files = scan_result["directories"].get(
                        "sensitive_files_found", []
                    )
                    if sensitive_files:
                        story.append(
                            Paragraph("Sensitive Files Found", styles["Heading3"])
                        )
                        story.append(Spacer(1, 6))

                        file_data = [["Path", "Type", "Description"]]
                        for file in sensitive_files:
                            file_data.append(
                                [
                                    wrap_text(file.get("path", "Unknown")),
                                    wrap_text(file.get("type", "Unknown")),
                                    wrap_text(file.get("description", "Unknown")),
                                ]
                            )

                        file_table = Table(
                            file_data, colWidths=[180, 80, effective_width - 260]
                        )
                        file_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(file_table)

                    story.append(Spacer(1, 12))

                # 6. LFI scan results
                if "lfi" in scan_result:
                    story.append(Paragraph("LFI Scan Results", heading2_style))
                    story.append(Spacer(1, 6))

                    vulnerabilities = scan_result["lfi"].get("vulnerable_endpoints", [])
                    if vulnerabilities:
                        vuln_data = [
                            ["URL", "Parameter", "Method", "Payload", "Severity"]
                        ]
                        for vuln in vulnerabilities:
                            vuln_data.append(
                                [
                                    wrap_text(vuln.get("url", "Unknown")),
                                    wrap_text(vuln.get("parameter", "Unknown")),
                                    wrap_text(vuln.get("method", "Unknown")),
                                    wrap_text(vuln.get("payload", "Unknown")),
                                    wrap_text(vuln.get("severity", "Unknown")),
                                ]
                            )

                        col_widths = [effective_width - 280, 70, 50, 100, 60]
                        vuln_table = Table(vuln_data, colWidths=col_widths)
                        vuln_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(vuln_table)

                    story.append(Spacer(1, 12))

                # 7. Command Injection scan results
                if "command_injection" in scan_result:
                    story.append(
                        Paragraph("Command Injection Scan Results", heading2_style)
                    )
                    story.append(Spacer(1, 6))

                    vulnerabilities = scan_result["command_injection"].get(
                        "vulnerable_endpoints", []
                    )
                    if vulnerabilities:
                        vuln_data = [
                            ["URL", "Parameter", "Method", "Payload", "Severity"]
                        ]
                        for vuln in vulnerabilities:
                            vuln_data.append(
                                [
                                    wrap_text(vuln.get("url", "Unknown")),
                                    wrap_text(vuln.get("parameter", "Unknown")),
                                    wrap_text(vuln.get("method", "Unknown")),
                                    wrap_text(vuln.get("payload", "Unknown")),
                                    wrap_text(vuln.get("severity", "Unknown")),
                                ]
                            )

                        col_widths = [effective_width - 280, 70, 50, 100, 60]
                        vuln_table = Table(vuln_data, colWidths=col_widths)
                        vuln_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(vuln_table)

                    story.append(Spacer(1, 12))

                # 8. Zone Transfer scan results
                if "zone_transfer" in scan_result:
                    story.append(
                        Paragraph("Zone Transfer Scan Results", heading2_style)
                    )
                    story.append(Spacer(1, 6))

                    transferable_domains = scan_result["zone_transfer"].get(
                        "transferable_domains", []
                    )
                    issues = scan_result["zone_transfer"].get("issues_found", [])

                    if transferable_domains:
                        story.append(
                            Paragraph("Transferable Domains", styles["Heading3"])
                        )
                        story.append(Spacer(1, 6))

                        domain_data = [["Domain"]]
                        for domain in transferable_domains:
                            domain_data.append([wrap_text(domain)])

                        domain_table = Table(domain_data, colWidths=[effective_width])
                        domain_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(domain_table)
                        story.append(Spacer(1, 6))

                    if issues:
                        story.append(
                            Paragraph("Zone Transfer Issues", styles["Heading3"])
                        )
                        story.append(Spacer(1, 6))

                        issue_data = [["Title", "Severity", "Description"]]
                        for issue in issues:
                            issue_data.append(
                                [
                                    wrap_text(issue.get("title", "Unknown")),
                                    wrap_text(issue.get("severity", "Unknown")),
                                    wrap_text(issue.get("description", "Unknown")),
                                ]
                            )

                        issue_table = Table(
                            issue_data, colWidths=[100, 70, effective_width - 170]
                        )
                        issue_table.setStyle(
                            TableStyle(
                                [
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ]
                            )
                        )
                        story.append(issue_table)

                    story.append(Spacer(1, 12))

                # 9. XSS scan results
                if "xss" in scan_result and scan_result["xss"]:
                    story.append(Paragraph("XSS Scan Results", heading2_style))
                    story.append(Spacer(1, 6))

                    for xss_result in scan_result["xss"]:
                        vulnerabilities = xss_result.get("vulnerable_endpoints", [])
                        if vulnerabilities:
                            vuln_data = [
                                ["URL", "Parameter", "Method", "Payload", "Severity"]
                            ]
                            for vuln in vulnerabilities:
                                vuln_data.append(
                                    [
                                        wrap_text(vuln.get("url", "Unknown")),
                                        wrap_text(vuln.get("parameter", "Unknown")),
                                        wrap_text(vuln.get("method", "Unknown")),
                                        wrap_text(vuln.get("payload", "Unknown")),
                                        wrap_text(vuln.get("severity", "Unknown")),
                                    ]
                                )

                            col_widths = [effective_width - 280, 70, 50, 100, 60]
                            vuln_table = Table(vuln_data, colWidths=col_widths)
                            vuln_table.setStyle(
                                TableStyle(
                                    [
                                        (
                                            "BACKGROUND",
                                            (0, 0),
                                            (-1, 0),
                                            colors.lightgrey,
                                        ),
                                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ]
                                )
                            )
                            story.append(vuln_table)
                            story.append(Spacer(1, 6))

                    story.append(Spacer(1, 12))

                # 10. SQLi scan results
                if "sqli" in scan_result and scan_result["sqli"]:
                    story.append(
                        Paragraph("SQL Injection Scan Results", heading2_style)
                    )
                    story.append(Spacer(1, 6))

                    for sqli_result in scan_result["sqli"]:
                        dbms_info = sqli_result.get("dbms_info")
                        if dbms_info:
                            story.append(
                                Paragraph(
                                    f"Detected Database: {dbms_info}", normal_style
                                )
                            )
                            story.append(Spacer(1, 6))

                        vulnerabilities = sqli_result.get("vulnerable_params", [])
                        if vulnerabilities:
                            vuln_data = [
                                ["URL", "Parameter", "Method", "Payload", "Type"]
                            ]
                            for vuln in vulnerabilities:
                                vuln_data.append(
                                    [
                                        wrap_text(vuln.get("url", "Unknown")),
                                        wrap_text(vuln.get("param", "Unknown")),
                                        wrap_text(vuln.get("method", "Unknown")),
                                        wrap_text(vuln.get("payload", "Unknown")),
                                        wrap_text(vuln.get("type", "Unknown")),
                                    ]
                                )

                            col_widths = [effective_width - 280, 70, 50, 100, 60]
                            vuln_table = Table(vuln_data, colWidths=col_widths)
                            vuln_table.setStyle(
                                TableStyle(
                                    [
                                        (
                                            "BACKGROUND",
                                            (0, 0),
                                            (-1, 0),
                                            colors.lightgrey,
                                        ),
                                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ]
                                )
                            )
                            story.append(vuln_table)

                    story.append(Spacer(1, 12))

                # Build PDF
                doc.build(story)

                # Reset buffer position
                buffer.seek(0)

                # Create response with PDF file
                filename = f"{filename_base}.pdf"
                media_type = "application/pdf"
                headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

                return Response(
                    content=buffer.getvalue(), media_type=media_type, headers=headers
                )
            except Exception as e:
                logger.error(f"Error generating PDF report: {e}")
                raise ValueError(f"Error generating PDF report: {str(e)}")
        else:
            raise ValueError(f"Unsupported report format: {report_format}")

    @staticmethod
    def convert_uuid_to_str(data):
        """
        Helper method to convert UUID objects to strings in complex data structures
        """
        if isinstance(data, dict):
            return {k: ScanService.convert_uuid_to_str(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [ScanService.convert_uuid_to_str(i) for i in data]
        elif isinstance(data, UUID):
            return str(data)
        else:
            return data
