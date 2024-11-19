import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import argparse
import json

def get_all_urls_from_website(base_url, cookies, visited_urls):
    session = requests.Session()
    session.cookies.update(cookies)
    
    if base_url in visited_urls:
        return []

    visited_urls.add(base_url)

    response = session.get(base_url)
    if response.status_code != 200:
        return []

    soup = BeautifulSoup(response.content, 'html.parser')

    links = soup.find_all('a', href=True)
    urls = []
    
    for link in links:
        url = link['href']
        full_url = urljoin(base_url, url)
        
        parsed_base_url = urlparse(base_url)
        parsed_full_url = urlparse(full_url)
        
        if parsed_base_url.netloc == parsed_full_url.netloc:
            if 'logout' in full_url.lower():
                print(f"Skipping logout URL: {full_url}")
                continue
            urls.append(full_url)

    return urls

def crawl(base_url, cookies):
    visited_urls = set()
    to_visit = [base_url]
    all_urls = []

    while to_visit:
        current_url = to_visit.pop(0)
        print(f"Crawling: {current_url}")
        
        urls = get_all_urls_from_website(current_url, cookies, visited_urls)
        all_urls.extend(urls)
        
        for url in urls:
            if url not in visited_urls:
                to_visit.append(url)
        
        time.sleep(1)

    return all_urls

def save_urls_to_file(urls, base_url):
    parsed_url = urlparse(base_url)
    domain = parsed_url.netloc
    filename = f"{domain.replace('.', '_')}_urls.txt"

    with open(filename, 'w') as file:
        for url in urls:
            file.write(url + '\n')

    print(f"All URLs saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crawl URLs from a website.")
    parser.add_argument("url", help="Base URL to start crawling.")
    parser.add_argument("cookies", help="Cookies to be used for the session. Provide as a JSON string.")
    
    args = parser.parse_args()

    # Parse cookies from the passed JSON string
    cookies = json.loads(args.cookies)
    
    # Start crawling from the base URL
    all_crawled_urls = crawl(args.url, cookies)

    # Save all crawled URLs to a file
    save_urls_to_file(all_crawled_urls, args.url)
