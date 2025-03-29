import os
import hashlib
import requests

MALICIOUS_HASH_FILE = "malicious_hashes.txt"

def load_malicious_hashes():
    """Load known malicious hashes from a local file (UTF-8 encoded)."""
    if not os.path.exists(MALICIOUS_HASH_FILE):
        return set()
    
    with open(MALICIOUS_HASH_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f)

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error reading file: {e}"

def check_virustotal(api_key, file_hash):
    """Check file hash on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            return f"⚠️ Malicious ({malicious_count} detections)" if malicious_count > 0 else "✅ Clean"
        elif response.status_code == 404:
            return "Hash not found in VirusTotal."
        elif response.status_code == 403:
            return "API quota exceeded. Try again later."
        else:
            return f"Error {response.status_code}: {response.json().get('error', {}).get('message', 'unknown error')}"
    except Exception as e:
        return f"Error querying VirusTotal: {e}"

def scan_directory(directory, api_key):
    """Scan directory, compute SHA-256, and check against local and VirusTotal databases."""
    if not os.path.exists(directory):
        print("Invalid directory. Please check the path.")
        return

    known_malicious_hashes = load_malicious_hashes()
    log_file = "scan_results.txt"

    with open(log_file, "w", encoding="utf-8") as log:
        log.write(f"Scan Report for {directory}\n")
        log.write("=" * 50 + "\n")

    print("\nScanning for .exe files in:", directory)
    found_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".exe"):
                file_path = os.path.join(root, file)
                file_hash = calculate_sha256(file_path)

                # Check in local malicious hash database first
                if file_hash in known_malicious_hashes:
                    result = "⚠️ Malicious (Found in local database)"
                else:
                    print(f"Checking {file} with VirusTotal...")
                    result = check_virustotal(api_key, file_hash)

                output = f"\nFile: {file}\nPath: {file_path}\nSHA-256: {file_hash}\nResult: {result}\n"
                print(output)

                with open(log_file, "a", encoding="utf-8") as log:
                    log.write(output + "\n")

    print(f"\nScan completed. Results saved in {log_file}")

# Get folder path and API key from user
folder_path = input("Enter the folder path to scan: ")
api_key = input("Enter your VirusTotal API key: ")
scan_directory(folder_path, api_key)
