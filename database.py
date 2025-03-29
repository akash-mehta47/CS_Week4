import requests

MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/txt/sha256/full/"

def download_malicious_hashes():
    """Download latest SHA-256 hashes of malware samples."""
    try:
        response = requests.get(MALWAREBAZAAR_URL)
        if response.status_code == 200:
            with open("malicious_hashes.txt", "w", encoding="utf-8") as file:
                file.write(response.text)
            print("✅ Malicious hash database updated successfully!")
        else:
            print(f"❌ Failed to fetch data. HTTP {response.status_code}")
    except Exception as e:
        print(f"Error downloading malicious hashes: {e}")

download_malicious_hashes()
