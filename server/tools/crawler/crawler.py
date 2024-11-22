import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
import time
import os

def login_to_website(base_url, cookies):
    """
    Logs into the website using the provided cookies.
    Returns a session object.
    """
    session = requests.Session()
    session.cookies.update(cookies)

    login_url = urljoin(base_url, "login.php")  # Adjust based on the website
    response = session.get(login_url, timeout=10)

    if response.status_code != 200:
        raise Exception(f"Failed to access login page: {login_url}")


    return session


def normalize_url(url):
    """
    Normalize the URL by removing fragments and ensuring consistent formatting.
    """
    url, _ = urldefrag(url)  # Remove fragments (e.g., #section)
    return url.rstrip('/')


def get_all_urls_from_website(base_url, session, visited_urls):
    """
    Scrapes all URLs from the provided base URL.
    """
    try:
        response = session.get(base_url, timeout=10)
        if response.status_code != 200:
            print(f"Skipping URL due to HTTP error {response.status_code}: {base_url}")
            return []

        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)
        urls = []

        for link in links:
            url = link['href']
            full_url = normalize_url(urljoin(base_url, url))
            parsed_base_url = urlparse(base_url)
            parsed_full_url = urlparse(full_url)

            # Only add valid, same-domain URLs
            if parsed_base_url.netloc == parsed_full_url.netloc and full_url not in visited_urls:
                if 'logout' not in full_url.lower():
                    urls.append(full_url)
        return urls

    except requests.RequestException as e:
        print(f"Error fetching URL {base_url}: {e}")
        return []


def crawl(base_url, cookies, max_depth=3):
    """
    Logs into the website and performs crawling with a depth limit.
    """
    visited_urls = set()
    to_visit = [(base_url, 0)]  # Include depth information
    all_urls = []

    try:
        session = login_to_website(base_url, cookies)
    except Exception as e:
        print(f"Login failed: {e}")
        return []

    while to_visit:
        current_url, depth = to_visit.pop(0)

        if current_url in visited_urls or depth > max_depth:
            continue


        visited_urls.add(current_url)

        # Fetch and process URLs
        urls = get_all_urls_from_website(current_url, session, visited_urls)


        all_urls.extend(urls)

        # Add new URLs to the queue for further crawling
        for url in urls:
            if url not in visited_urls:
                to_visit.append((url, depth + 1))

        # Respectful crawling delay
        time.sleep(1)
    return list(set(all_urls))


def save_urls_to_file(urls, base_url, output_dir):
    """
    Save the list of URLs to a file in the output directory.
    """
    parsed_url = urlparse(base_url)
    domain = parsed_url.netloc
    filename = f"{domain.replace('.', '_')}_urls.txt"
    file_path = os.path.join(output_dir, filename)

    with open(file_path, 'w') as file:
        for url in urls:
            file.write(url + '\n')

    return file_path
