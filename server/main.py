from fastapi import FastAPI, HTTPException, Query
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
from urllib.parse import urlparse


# Directory to store output files
OUTPUT_DIR = "./output"
FINAL_REPORT_DIR = "./finalreport"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(FINAL_REPORT_DIR, exist_ok=True)


class Cookie(BaseModel):
    name: str
    value: str


class CrawlRequest(BaseModel):
    website_url: str
    email: str
    cookies: List[Cookie]


class ReportRequest(BaseModel):
    website_url: str


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
    try:
        website_url = request.website_url
        email = request.email
        cookies = {cookie.name: cookie.value for cookie in request.cookies}

        crawled_urls = crawl(website_url, cookies)

        # Save crawled URLs to a file
        output_file = save_urls_to_file(crawled_urls, website_url, OUTPUT_DIR)

        # Perform vulnerability scans
        sql_scan_from_file(output_file, cookies)
        xss_scan_from_file(output_file, cookies)
        lfi_scan_from_file(output_file, cookies)
        cmd_injection_scan_from_file(output_file, cookies)
        run_wpscan(website_url, WP_SCAN)

        return {
            "message": "Crawling and scanning completed successfully.",
            "crawled_urls_file": output_file,
            "total_urls_found": len(crawled_urls),
        }
    except Exception as e:
        print(f"Error during crawling: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/combined-report")
async def get_combined_report(request: ReportRequest):
    try:
        # Extract and sanitize the website URL
        website_url = request.website_url
        parsed_url = urlparse(website_url)
        domain = parsed_url.netloc.replace(".", "_")
        sanitized_url = domain

        # Define scan directories and file suffixes
        scan_directories = {
            "SQLi": os.path.join(OUTPUT_DIR, "sql_scans"),
            "XSS": os.path.join(OUTPUT_DIR, "xss_scans"),
            "LFI": os.path.join(OUTPUT_DIR, "lfi_scans"),
            "CMD": os.path.join(OUTPUT_DIR, "cmd_scans"),
            "WordPress": os.path.join(OUTPUT_DIR, "wp_scans"),
        }
        file_suffixes = {
            "SQLi": "_urls_sql.txt",
            "XSS": "_urls_xss.txt",
            "LFI": "_urls_lfi.txt",
            "CMD": "_urls_cmd.txt",
            "WordPress": "__wpscan.txt",
        }

        vulnerabilities = []
        filtered_vulnerabilities = []  # Store only found vulnerabilities for frontend
        counts = {key: 0 for key in scan_directories.keys()}

        # If no files exist, return an error
        files_found = False
        for scan_type, directory in scan_directories.items():
            if not os.path.exists(directory):
                continue

            if scan_type == "WordPress":
                for filename in os.listdir(directory):
                    if filename.startswith(sanitized_url) and filename.endswith(
                        file_suffixes[scan_type]
                    ):
                        scan_file = os.path.join(directory, filename)
                        with open(scan_file, "r") as f:
                            lines = f.readlines()
                            for line in lines:
                                detail = line.strip()
                                vulnerabilities.append(
                                    {"type": scan_type, "detail": detail}
                                )
                                if "vulnerability found" in detail:
                                    filtered_vulnerabilities.append(
                                        {"type": scan_type, "detail": detail}
                                    )
                            counts[scan_type] += len(lines)
                        files_found = True
                        break
            else:
                scan_file = os.path.join(
                    directory, f"{sanitized_url}{file_suffixes[scan_type]}"
                )
                if os.path.exists(scan_file):
                    with open(scan_file, "r") as f:
                        lines = f.readlines()
                        for line in lines:
                            detail = line.strip()
                            vulnerabilities.append(
                                {"type": scan_type, "detail": detail}
                            )
                            if "vulnerability found" in detail:
                                filtered_vulnerabilities.append(
                                    {"type": scan_type, "detail": detail}
                                )
                        counts[scan_type] += len(lines)
                    files_found = True

        if not files_found:
            raise HTTPException(
                status_code=404,
                detail="No vulnerabilities found. Please scan the website first.",
            )

        # Create a summary
        filtered_counts = {k: v for k, v in counts.items() if v > 0}

        # Create the combined report file
        report_filename = f"{sanitized_url}_combined_report.txt"
        combined_report_path = os.path.join(FINAL_REPORT_DIR, report_filename)

        with open(combined_report_path, "w") as report_file:
            report_file.write(f"Combined Vulnerability Report for {website_url}\n\n")
            report_file.write("Summary:\n")
            for vuln_type, count in filtered_counts.items():
                report_file.write(f"- {vuln_type}: {count}\n")
            report_file.write(
                f"\nTotal Vulnerabilities: {sum(filtered_counts.values())}\n\n"
            )

            report_file.write("Details:\n")
            for (
                vuln
            ) in (
                vulnerabilities
            ):  # Write all vulnerabilities (both found and not found)
                report_file.write(f"[{vuln['type']}] {vuln['detail']}\n")

        response = {
            "website_url": f"/api/download?filename={report_filename}",
            "total_vulnerabilities": len(filtered_vulnerabilities),
            "summary": {k: v for k, v in filtered_counts.items() if v > 0},
            "details": filtered_vulnerabilities,  # Only include found vulnerabilities
        }

        return response

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate the report.")


@app.get("/api/download")
async def download_report(
    filename: str = Query(..., description="The name of the report file to download.")
):
    try:
        file_path = os.path.join(FINAL_REPORT_DIR, filename)
        print(file_path)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found.")

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="text/plain",
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Error serving file: {e}")
        raise HTTPException(status_code=500, detail="Failed to download the file.")
