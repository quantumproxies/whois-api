"""Minimal WHOIS / RDAP domain lookup API call — one typed row per domain.

Docs & schema: https://quanticdata.io/collectors/whois-api/
"""
import json
import os

import requests

API = "https://api.quanticdata.io/v1/scraper/collectors/whois_domain/run"
KEY = os.environ["QD_API_KEY"]  # https://quanticdata.io/

payload = {
        "domains": [
            "google.com"
        ],
        "max_results": 1
    }

r = requests.post(
    API,
    headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    json=payload,
    timeout=180,
)
r.raise_for_status()
data = r.json()["payload"]

for row in data["results"]:
    print(row.get("domain"), row.get("registrar"), row.get("registrar_iana_id"))
print(f"{len(data['results'])} domains, cost ${data['cost']}")
