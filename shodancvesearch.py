import requests
import sys
import json

def fetch_cve_info(cve_id):
    url = f"https://cvedb.shodan.io/cve/{cve_id}"
    
    try:
        response = requests.get(url, timeout=10)  # Set timeout to avoid hanging requests
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx, 5xx)
        
        try:
            cve_data = response.json()
            return cve_data
        except json.JSONDecodeError:
            print("Error: Response is not valid JSON")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <CVE-ID>")
        sys.exit(1)

    cve_id = sys.argv[1]  # Take CVE-ID from command-line argument
    cve_info = fetch_cve_info(cve_id)

    if cve_info:
        print(json.dumps(cve_info, indent=4))  # Pretty print the JSON response
