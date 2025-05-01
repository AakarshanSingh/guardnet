import logging
import asyncio
import threading
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
import json
import urllib.parse

from app.scanners.web_crawler import WebCrawler
from app.scanners.lfi_scanner import LFIScanner
from app.scanners.sqli_scanner import SQLiScanner
from app.scanners.xss_scanner import XSSScanner
from app.models.website import Website, WebsiteUrl
from app.models.scan import Scan, LFIResult, SQLiResult, XSSResult
from app.utils.browser_manager import browser_manager

logger = logging.getLogger(__name__)


class VulnerabilityScanCoordinator:
    """
    Coordinates the crawling and vulnerability scanning process for LFI, SQLi, and XSS.
    Uses the WebCrawler to discover potential targets, then scans them for vulnerabilities.
    """

    def __init__(self, db: Session, scan_id: Any, website: Website):
        """
        Initialize the vulnerability scan coordinator.

        Args:
            db: Database session
            scan_id: ID of the scan being performed
            website: Website object from the database
        """
        self.db = db
        self.scan_id = scan_id
        self.website = website
        self.url = website.url
        self.cookies = website.cookies

        # Tracking containers
        self.crawl_results = None
        self.website_urls = {}
        self.scan_complete = threading.Event()

    async def run_scan(self):
        """Run the complete crawl and scan process"""
        logger.info(f"Starting vulnerability scan for {self.url}")

        try:
            # Start the crawler in a separate thread
            crawler_thread = threading.Thread(target=self._run_crawler)
            crawler_thread.daemon = True
            crawler_thread.start()

            # Wait for crawler to finish or timeout
            crawler_thread.join(timeout=600)  # 10 minute timeout for crawling

            if crawler_thread.is_alive():
                logger.warning(
                    f"Crawler for {self.url} is taking too long, proceeding with current results"
                )

            if not self.crawl_results:
                logger.error(f"Crawler failed to produce results for {self.url}")
                return

            # Save discovered URLs to database
            self._save_website_urls()

            # Run vulnerability scans in parallel
            await asyncio.gather(
                self._run_sqli_scan(),
                self._run_xss_scan(),
                self._run_lfi_scan(),
            )

            logger.info(f"Vulnerability scan completed for {self.url}")

        except Exception as e:
            logger.error(f"Error during vulnerability scan: {str(e)}", exc_info=True)
        finally:
            # Signal completion
            self.scan_complete.set()

    def _run_crawler(self):
        """Run the web crawler to discover potential targets"""
        try:
            # Parse the URL to get domain information for cookies
            parsed_url = urllib.parse.urlparse(self.url)
            domain = parsed_url.netloc

            logger.info(f"Starting web crawler for {self.url}")

            crawler = WebCrawler(
                base_url=self.url,
                cookies=self.cookies,
                max_pages=100,  # Limit to 100 pages for performance
                max_depth=3,  # Limit depth to 3 levels
                scan_external=False,
                threads=3,  # Use 3 crawler threads
            )

            # Start crawling
            self.crawl_results = crawler.start_crawl()
            logger.info(
                f"Crawling completed for {self.url}, found {len(self.crawl_results.get('visited_urls', []))} URLs"
            )

        except Exception as e:
            logger.error(f"Error during web crawling: {str(e)}", exc_info=True)
            # Create minimal results if crawling failed completely
            if not self.crawl_results:
                self.crawl_results = {
                    "visited_urls": [self.url],
                    "forms_found": [],
                    "inputs_found": [],
                    "parameters_found": {},
                }
                logger.info(f"Created minimal crawl results after error for {self.url}")

    def _save_website_urls(self):
        """Save discovered URLs to database for future reference"""
        try:
            if not self.crawl_results:
                return

            # Create WebsiteUrl entries for all discovered URLs
            for url in self.crawl_results.get("visited_urls", []):
                # Skip invalid URLs
                if not url or not url.startswith(("http://", "https://")):
                    continue

                # Create or get website URL entry
                website_url = (
                    self.db.query(WebsiteUrl)
                    .filter(
                        WebsiteUrl.website_id == self.website.id, WebsiteUrl.url == url
                    )
                    .first()
                )

                if not website_url:
                    website_url = WebsiteUrl(website_id=self.website.id, url=url)
                    self.db.add(website_url)

                # Save parameters if found
                if url in self.crawl_results.get("parameters_found", {}):
                    website_url.parameters = json.dumps(
                        self.crawl_results["parameters_found"][url]
                    )

                self.db.commit()
                self.db.refresh(website_url)

                # Store for later use during scanning
                self.website_urls[url] = website_url

            logger.info(f"Saved {len(self.website_urls)} URLs to database")

        except Exception as e:
            logger.error(f"Error saving website URLs: {str(e)}", exc_info=True)
            self.db.rollback()

    async def _run_lfi_scan(self):
        """Run LFI scanning on discovered URLs and forms"""
        try:
            if not self.crawl_results:
                return

            logger.info(f"Starting LFI scan for {self.url}")

            # Create scanner
            lfi_scanner = LFIScanner(self.url, self.cookies)

            # Inject form targets from crawler results
            form_targets = []
            for form in self.crawl_results.get("forms_found", []):
                form_targets.append(
                    {
                        "url": form["action"],
                        "method": form["method"],
                        "params": [
                            input_field["name"] for input_field in form["inputs"]
                        ],
                    }
                )

            # Add URL parameter targets
            for url, params in self.crawl_results.get("parameters_found", {}).items():
                form_targets.append({"url": url, "method": "get", "params": params})

            # Set targets and run scan
            lfi_scanner.injectable_targets = form_targets
            results = lfi_scanner.run()

            # Save results to database
            lfi_result = LFIResult(
                scan_id=self.scan_id,
                vulnerable_endpoints=json.dumps(
                    results.get("vulnerable_endpoints", [])
                ),
            )
            self.db.add(lfi_result)
            self.db.commit()

            logger.info(
                f"LFI scan completed for {self.url}, found {len(results.get('vulnerable_endpoints', []))} vulnerabilities"
            )

        except Exception as e:
            logger.error(f"Error during LFI scan: {str(e)}", exc_info=True)
            self.db.rollback()

    async def _run_sqli_scan(self):
        """Run SQLi scanning on discovered URLs and forms"""
        try:
            if not self.crawl_results:
                return

            logger.info(f"Starting SQLi scan for {self.url}")

            # Create scanner
            sqli_scanner = SQLiScanner(self.url, self.cookies)

            # Inject form targets from crawler results
            form_targets = []
            for form in self.crawl_results.get("forms_found", []):
                form_targets.append(
                    {
                        "url": form["action"],
                        "method": form["method"],
                        "params": [
                            input_field["name"] for input_field in form["inputs"]
                        ],
                    }
                )

            # Add URL parameter targets
            for url, params in self.crawl_results.get("parameters_found", {}).items():
                form_targets.append({"url": url, "method": "get", "params": params})

            # Set targets and run scan
            sqli_scanner.injectable_targets = form_targets
            results = sqli_scanner.run()

            # Process results for each URL
            vulnerable_endpoints = results.get("vulnerable_params", [])

            # Group results by URL for saving to database
            for url, website_url_obj in self.website_urls.items():
                # Find vulnerabilities for this URL
                url_vulns = [v for v in vulnerable_endpoints if v.get("url") == url]

                if url_vulns:
                    # Create SQLi result for this URL
                    sqli_result = SQLiResult(
                        website_url_id=website_url_obj.id,
                        vulnerable_params=json.dumps(url_vulns),
                        dbms_info=results.get("dbms_info", ""),
                        payloads_used=json.dumps(results.get("payloads_used", [])),
                    )
                    self.db.add(sqli_result)
                    self.db.commit()

            logger.info(
                f"SQLi scan completed for {self.url}, found {len(vulnerable_endpoints)} vulnerabilities"
            )

        except Exception as e:
            logger.error(f"Error during SQLi scan: {str(e)}", exc_info=True)
            self.db.rollback()

    async def _run_xss_scan(self):
        """Run XSS scanning on discovered URLs and forms"""
        try:
            if not self.crawl_results:
                return

            logger.info(f"Starting XSS scan for {self.url}")

            # Create scanner
            xss_scanner = XSSScanner(self.url, self.cookies)

            # Inject form targets from crawler results
            form_targets = []
            for form in self.crawl_results.get("forms_found", []):
                form_targets.append(
                    {
                        "url": form["action"],
                        "method": form["method"],
                        "params": [
                            input_field["name"] for input_field in form["inputs"]
                        ],
                    }
                )

            # Add URL parameter targets
            for url, params in self.crawl_results.get("parameters_found", {}).items():
                form_targets.append({"url": url, "method": "get", "params": params})

            # Set targets and run scan
            xss_scanner.form_targets = form_targets
            results = xss_scanner.run()

            # Process results for each URL
            vulnerable_endpoints = results.get("vulnerable_endpoints", [])

            # Group results by URL for saving to database
            for url, website_url_obj in self.website_urls.items():
                # Find vulnerabilities for this URL
                url_vulns = [v for v in vulnerable_endpoints if v.get("url") == url]

                if url_vulns:
                    # Create XSS result for this URL
                    xss_result = XSSResult(
                        website_url_id=website_url_obj.id,
                        vulnerable_endpoints=json.dumps(url_vulns),
                        payloads_used=json.dumps(results.get("payloads_used", [])),
                    )
                    self.db.add(xss_result)
                    self.db.commit()

            logger.info(
                f"XSS scan completed for {self.url}, found {len(vulnerable_endpoints)} vulnerabilities"
            )

        except Exception as e:
            logger.error(f"Error during XSS scan: {str(e)}", exc_info=True)
            self.db.rollback()

    def wait_for_completion(self, timeout=None):
        """Wait for the scan to complete"""
        return self.scan_complete.wait(timeout=timeout)
