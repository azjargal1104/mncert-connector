import requests
import urllib3
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

# Fetch and push MNCERT data
def fetch_and_push_mncert_data():
    try:
        response = requests.get(f"{MNCERT_API_URL}?apikey={MNCERT_API_KEY}")
        if response.status_code == 200:
            data = response.json()
            print("Fetched data from MNCERT:", data)
            for item in data:
                ip_address = item.get("ip")
                description = item.get("description", "MNCERT CTI Data")
                if ip_address:
                    indicator = opencti_client.indicator.create(
                        name=f"Suspicious IP: {ip_address}",
                        description=description,
                        pattern=f"[ipv4-addr:value = '{ip_address}']",
                        pattern_type="stix",
                        confidence=70,
                        created=datetime.now(timezone.utc).isoformat(),
                    )
                    print(f"Indicator created: {indicator['id']}")
        else:
            print(f"Failed to fetch data from MNCERT: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

# Run once
fetch_and_push_mncert_data()
       
