import os
import subprocess

def run_wpscan(target_url, api_token, output_dir="./output/wp_scans"):
    """
    Runs WPScan against the given target URL and saves the output to a file.

    Args:
        target_url (str): The WordPress site URL to scan.
        api_token (str): The WPScan API token for accessing the vulnerability database.
        output_dir (str): Directory to save the scan results.
    
    Returns:
        str: The path to the result file.
    """
    try:
        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Prepare the output file path
        base_url = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
        result_file_path = os.path.join(output_dir, f"{base_url}_wpscan.txt")

        # WPScan command
        command = [
            "wpscan",
            "--url", target_url,
            "--api-token", api_token,
            "--no-banner",
            "--disable-tls-checks"
        ]

        # Run the command
        with open(result_file_path, "w") as result_file:
            process = subprocess.run(command, stdout=result_file, stderr=subprocess.STDOUT, text=True)

        # Check for errors in the process
        if process.returncode != 0:
            print(f"[!] WPScan encountered an error. Check the log file: {result_file_path}")

        print(f"[+] WPScan results saved to: {result_file_path}")
        return result_file_path

    except Exception as e:
        print(f"[!] Error running WPScan: {e}")
        return None

# Example usage
if __name__ == "__main__":
    target_url = input("Enter the WordPress site URL: ").strip()
    api_token = input("Enter your WPScan API token: ").strip()

    result_path = run_wpscan(target_url, api_token)
    if result_path:
        print(f"Results saved to: {result_path}")
