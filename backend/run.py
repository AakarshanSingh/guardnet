import subprocess
import sys
import json
import os

# Define paths
EXTRACT_URL_SCRIPT = 'url/crawler.py'
SQL_SCRIPT_PATH = 'scanner/sql/sql.py'

# Function to run the extract_url.py script
def run_crawler(url, cookies):
    cookies_json = json.dumps(cookies)
    
    command = [
        'python3', EXTRACT_URL_SCRIPT,  # Script to execute
        url,                            # URL to scan
        cookies_json                   # Cookies in JSON format
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.stdout:
        print(f"Extracted URLs:\n{result.stdout}")
    if result.stderr:
        print(f"Error running extract_url.py: {result.stderr}", file=sys.stderr)
    
    return result.stdout

# Function to run the SQL script and scan for vulnerabilities
def run_sql_injection_script(url, cookies):
    command = [
        'python3', SQL_SCRIPT_PATH,  # SQL injection scan script
        url                          # URL to scan
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.stdout:
        print(f"SQL Injection Results:\n{result.stdout}")
    if result.stderr:
        print(f"Error running sql.py: {result.stderr}", file=sys.stderr)
    
    return result.stdout

# Function to read URLs from a file
def read_urls_from_file(filename):
    with open(filename, 'r') as file:
        urls = file.readlines()
    return [url.strip() for url in urls if url.strip()]

# Function to save the output to a file
def save_output_to_file(output, filename):
    with open(filename, 'w') as file:
        file.write(output)

if __name__ == "__main__":
    # Ensure proper arguments are passed
    if len(sys.argv) != 4:
        print("Usage: python run.py <url_file> <cookies> <output_file>")
        sys.exit(1)
    
    url_file = sys.argv[1]
    cookies_str = sys.argv[2]
    output_file = sys.argv[3]
    
    # Convert cookies from string to a dictionary
    try:
        cookies = json.loads(cookies_str)
    except json.JSONDecodeError as e:
        print(f"Invalid cookies format: {e}")
        sys.exit(1)
    
    # Step 1: Read URLs from file
    urls = read_urls_from_file(url_file)
    
    full_output = ""
    
    # Step 2: Run the crawler and scan each URL
    for url in urls:
        print(f"\nRunning scan for: {url}")
        
        # Run the crawler and extract additional URLs (if needed)
        extracted_urls = run_crawler(url, cookies)
        
        # Run the SQL injection scan and other vulnerability checks
        scan_results = run_sql_injection_script(url, cookies)
        
        # Save the results to the full output
        full_output += f"\nResults for URL: {url}\n"
        full_output += f"Extracted URLs:\n{extracted_urls}\n"
        full_output += f"SQL Injection Scan Results:\n{scan_results}\n"
    
    # Step 3: Save the results to the output file
    save_output_to_file(full_output, output_file)
    print(f"Results saved to {output_file}")
