
import json
from pathlib import Path
from datetime import datetime, timezone

import requests

API_URL = "https://api.osv.dev/v1/querybatch"

PACKAGES = [
    {"name": "requests", "ecosystem": "PyPI", "version": "2.28.0"},
    {"name": "django", "ecosystem": "PyPI", "version": "4.1.0"},
    {"name": "flask", "ecosystem": "PyPI", "version": "2.2.0"},
    {"name": "urllib3", "ecosystem": "PyPI", "version": "1.26.5"},
    {"name": "pillow", "ecosystem": "PyPI", "version": "9.0.0"},
]

queries = [
    {
        "package": {
            "name": p["name"],
            "ecosystem": p["ecosystem"],
        },
        "version": p["version"],
    }
    for p in PACKAGES
]

response = requests.post(
    API_URL,
    json={"queries": queries},
    timeout=60,
)
response.raise_for_status()

results = response.json()["results"]

records = []
for package, result in zip(PACKAGES, results):
    for vulnerability in result.get("vulns", []):
        records.append({
            "package": package,
            "vulnerability": vulnerability,
        })

output = {
    "source": "OSV.dev",
    "retrieved_at": datetime.now(timezone.utc).isoformat(),
    "packages_checked": PACKAGES,
    "records": records,
}

output_path = Path(__file__).parent / "raw" / "osv_vulnerabilities.json"
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

print(f"Packages checked: {len(PACKAGES)}")
print(f"Vulnerability records found: {len(records)}")
print(f"Saved to: {output_path.resolve()}")