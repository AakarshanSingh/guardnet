from fastapi import FastAPI, HTTPException
import os
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from tools.crawler.crawler import crawl, save_urls_to_file
from tools.scanner.sql import sql_scan_from_file  # Import the new SQL scanning function
from tools.scanner.xss import xss_scan_from_file
from tools.scanner.lfi import lfi_scan_from_file 
from tools.scanner.cmd import cmd_injection_scan_from_file
from typing import List

# Directory to store output files
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class Cookie(BaseModel):
    name: str
    value: str
    
class CrawlRequest(BaseModel):
    website_url: str
    email: str
    cookies: List[Cookie]

app = FastAPI()

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
        

        return {
            "message": "Crawling and SQL injection scan completed successfully.",
            "crawled_urls_file": output_file,
            "total_urls_found": len(crawled_urls),
        }
    except Exception as e:
        print(f"Error during crawling: {e}")
        raise HTTPException(status_code=500, detail=str(e))
