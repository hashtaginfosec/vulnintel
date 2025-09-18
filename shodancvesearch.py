import json
import re
import sys

import requests

_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _validate_cve_id(cve_id):
    if not isinstance(cve_id, str):
        raise ValueError("CVE ID must be provided as a string")

    if not _CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError("Invalid CVE ID format. Expected value like 'CVE-2021-44228'.")

    return cve_id.upper()


def fetch_cve_info(cve_id):
    cve_id = _validate_cve_id(cve_id)
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

    try:
        cve_id = _validate_cve_id(sys.argv[1])  # Take CVE-ID from command-line argument
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    cve_info = fetch_cve_info(cve_id)

    if cve_info:
        print(json.dumps(cve_info, indent=4))  # Pretty print the JSON response
