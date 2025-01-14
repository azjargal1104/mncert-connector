import requests
import urllib3
import os
from datetime import datetime, timezone
from pycti import OpenCTIApiClient

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# OpenCTI configuration
OPENCTI_URL = "https://172.29.60.45"
OPENCTI_API_TOKEN = "1468f4da-a035-4c9e-8494-237034167a84"
MNCERT_API_URL = "https://arctic.alert.mn:8443/shares/v2/917133d8-6688-4d71-8c41-0747a95156e5"
MNCERT_API_KEY = "e455eb85-fbcd-4f68-83f6-9385c6e7d035"

# Initialize OpenCTI client
opencti_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_API_TOKEN)

# Load the UUIDs of previously processed events to avoid duplicates
processed_events_file = "processed_events.json"
if os.path.exists(processed_events_file):
    with open(processed_events_file, "r") as f:
        processed_events = json.load(f)
else:
    processed_events = []

# Save processed events to file
def save_processed_events():
    with open(processed_events_file, "w") as f:
        json.dump(processed_events, f)

# Fetch and process MNCERT data
def fetch_and_process_mncert_data():
    try:
        response = requests.get(f"{MNCERT_API_URL}?apikey={MNCERT_API_KEY}")
        if response.status_code == 200:
            data = response.json()
            print("Fetched data from MNCERT:", json.dumps(data, indent=2))

            for item in data:
                uuid = item.get("uuid")
                if uuid in processed_events:
                    continue  # Skip already processed events

                ip = item.get("ip")
                url = item.get("matched event value")
                description = item.get("description", "MNCERT CTI Data")
                severity = item.get("reported severity", "info")

                if ip:
                    indicator = opencti_client.indicator.create(
                        name=f"Suspicious IP: {ip}",
                        description=description,
                        pattern=f"[ipv4-addr:value = '{ip}']",
                        pattern_type="stix",
                        x_opencti_main_observable_type="IPv4-Addr",
                        confidence=70,
                        x_opencti_severity=severity,
                        labels=["public exposure", "mncert"],
                        valid_from=datetime.now(timezone.utc).isoformat(),
                    )
                    print(f"Indicator created: {indicator['id']}")
                elif url:
                    indicator = opencti_client.indicator.create(
                        name=f"Suspicious URL: {url}",
                        description=description,
                        pattern=f"[url:value = '{url}']",
                        pattern_type="stix",
                        x_opencti_main_observable_type="URL",
                        confidence=70,
                        x_opencti_severity=severity,
                        labels=["phishing", "mncert"],
                        valid_from=datetime.now(timezone.utc).isoformat(),
                    )
                    print(f"Indicator created: {indicator['id']}")

                processed_events.append(uuid)

            save_processed_events()
        else:
            print(f"Failed to fetch data from MNCERT: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

# Run the function
fetch_and_process_mncert_data()

# Run once
fetch_and_push_mncert_data()
