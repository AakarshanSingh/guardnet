from fastapi import FastAPI, HTTPException
import os
from pydantic import BaseModel
from tools.crawler.crawler import crawl, save_urls_to_file
from tools.scanner.sql import scan_urls_from_file  # Import the new SQL scanning function

# Directory to store output files
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Define the request model
class CrawlRequest(BaseModel):
    website_url: str
    email: str
    cookies: dict

app = FastAPI()

@app.post("/api/crawl")
async def crawl_website(request: CrawlRequest):
    """
    Endpoint to crawl a website, save URLs, and associate results with a user's email.
    """
    try:
        # Extract parameters from the request body
        website_url = request.website_url
        email = request.email
        cookies = request.cookies

        # Step 1: Run the crawler
        crawled_urls = crawl(website_url, cookies)

        # Step 2: Save crawled URLs to a file
        output_file = save_urls_to_file(crawled_urls, website_url, OUTPUT_DIR)

        # Step 3: Scan the URLs from the output file for SQL Injection vulnerabilities

        scan_urls_from_file(output_file, cookies)


        return {
            "message": "Crawling and SQL injection scan completed successfully.",
            "crawled_urls_file": output_file,
            "total_urls_found": len(crawled_urls),
        }
    except Exception as e:
        print(f"Error during crawling: {e}")
        raise HTTPException(status_code=500, detail=str(e))
