from fastapi import FastAPI, HTTPException
import os
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from tools.crawler.crawler import crawl, save_urls_to_file
from tools.scanner.sql import sql_scan_from_file
from tools.scanner.xss import xss_scan_from_file
from tools.scanner.lfi import lfi_scan_from_file
from tools.scanner.cmd import cmd_injection_scan_from_file
from tools.scanner.wp import run_wpscan
from dotenv import load_dotenv
from typing import List
from fastapi.responses import FileResponse


# Directory to store output files
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)
SCANS_DIR = os.path.join(OUTPUT_DIR, "scans")
SUMMARY_FILE = os.path.join(OUTPUT_DIR, "combined_report.txt")

class Cookie(BaseModel):
    name: str
    value: str


class CrawlRequest(BaseModel):
    website_url: str
    email: str
    cookies: List[Cookie]


app = FastAPI()

load_dotenv()

WP_SCAN = os.getenv("WP_SCAN")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/scan")
async def crawl_website(request: CrawlRequest):
    """
    Endpoint to crawl a website, save URLs, and associate results with a user's email.
    """
    try:
        # Extract parameters from the request body
        website_url = request.website_url
        email = request.email
        cookies = {cookie.name: cookie.value for cookie in request.cookies}

        crawled_urls = crawl(website_url, cookies)

        # Step 2: Save crawled URLs to a file
        output_file = save_urls_to_file(crawled_urls, website_url, OUTPUT_DIR)

        # Step 3: Scan the URLs from the output file for SQL Injection vulnerabilities

        sql_scan_from_file(output_file, cookies)
        xss_scan_from_file(output_file, cookies)
        lfi_scan_from_file(output_file, cookies)
        cmd_injection_scan_from_file(output_file, cookies)
        run_wpscan(website_url, WP_SCAN)

        return {
            "message": "Crawling and SQL injection scan completed successfully.",
            "crawled_urls_file": output_file,
            "total_urls_found": len(crawled_urls),
        }
    except Exception as e:
        print(f"Error during crawling: {e}")
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/api/combined-report")
async def get_combined_report():
    """
    Combines all vulnerability scan results into a single file and returns it.
    """
    try:
        # Ensure directories exist
        os.makedirs(SCANS_DIR, exist_ok=True)

        # List of files to combine
        scan_files = [
            os.path.join(SCANS_DIR, "sql_scan.txt"),
            os.path.join(SCANS_DIR, "xss_scan.txt"),
            os.path.join(SCANS_DIR, "lfi_scan.txt"),
            os.path.join(SCANS_DIR, "cmd_scan.txt"),
            os.path.join(SCANS_DIR, "wpscan.txt"),
        ]

        vulnerabilities = []  # To store all vulnerability details
        counts = {"SQLi": 0, "XSS": 0, "LFI": 0, "CMD": 0, "WordPress": 0}

        # Read all scan files and aggregate vulnerabilities
        for scan_file in scan_files:
            if os.path.exists(scan_file):
                with open(scan_file, "r") as f:
                    lines = f.readlines()
                    vulnerabilities.extend(lines)

                    # Count vulnerabilities for each type
                    if "sql_scan" in scan_file:
                        counts["SQLi"] += len(lines)
                    elif "xss_scan" in scan_file:
                        counts["XSS"] += len(lines)
                    elif "lfi_scan" in scan_file:
                        counts["LFI"] += len(lines)
                    elif "cmd_scan" in scan_file:
                        counts["CMD"] += len(lines)
                    elif "wpscan" in scan_file:
                        counts["WordPress"] += len(lines)

        # Write the combined report
        with open(SUMMARY_FILE, "w") as summary:
            summary.write("GuardNet Combined Vulnerability Report\n")
            summary.write("=" * 40 + "\n\n")
            summary.write(f"Total Vulnerabilities: {sum(counts.values())}\n\n")
            for scan_type, count in counts.items():
                summary.write(f"{scan_type} Vulnerabilities: {count}\n")
            summary.write("\nDetailed Vulnerabilities:\n")
            summary.write("=" * 40 + "\n")
            summary.writelines(vulnerabilities)

        # Send the report as a downloadable file
        return FileResponse(SUMMARY_FILE, filename="combined_report.txt")

    except Exception as e:
        print(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report.")
