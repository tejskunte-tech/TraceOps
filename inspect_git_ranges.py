
import json
from pathlib import Path

path = Path("data/raw/osv_detailed.json")

with path.open(encoding="utf-8") as f:
    data = json.load(f)

records = data.get("records", []) if isinstance(data, dict) else data

print("\n===== Git Range Investigation =====")

count = 0

for record in records:
    package = record.get("package_checked", {})
    vulnerability = record.get("vulnerability", {})

    for affected in vulnerability.get("affected", []):
        for version_range in affected.get("ranges", []):
            if version_range.get("type") != "GIT":
                continue

            count += 1
            print(f"\nPackage: {package.get('name')}")
            print(f"Installed version: {package.get('version')}")
            print(f"Advisory: {vulnerability.get('id')}")
            print(f"Summary: {vulnerability.get('summary', '')}")
            print("Git range events:")

            for event in version_range.get("events", []):
                print(f"  {event}")

print(f"\nTotal Git ranges found: {count}")