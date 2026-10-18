
import json
import time
from pathlib import Path

import requests

DATA_DIR = Path(__file__).resolve().parent
INPUT_FILE = DATA_DIR / "raw" / "osv_vulnerabilities.json"
OUTPUT_FILE = DATA_DIR / "raw" / "osv_detailed.json"

API_URL = "https://api.osv.dev/v1/vulns/{}"


def main():
    data = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

    # Keep one entry for each unique vulnerability ID.
    unique = {}

    for record in data["records"]:
        vuln = record["vulnerability"]
        vuln_id = vuln.get("id")

        if vuln_id:
            unique.setdefault(vuln_id, record["package"])

    detailed_records = []

    print(f"Found {len(unique)} unique vulnerability IDs.")

    for index, (vuln_id, package) in enumerate(unique.items(), start=1):
        try:
            response = requests.get(
                API_URL.format(vuln_id),
                timeout=30,
            )

            if response.status_code == 404:
                print(f"[{index}/{len(unique)}] Not found: {vuln_id}")
                continue

            response.raise_for_status()
            vuln = response.json()

            detailed_records.append({
                "package_checked": package,
                "vulnerability": vuln,
                "source_url": f"https://osv.dev/vulnerability/{vuln_id}",
            })

            print(f"[{index}/{len(unique)}] Downloaded {vuln_id}")

        except requests.RequestException as error:
            print(f"Could not download {vuln_id}: {error}")

        # Avoid sending requests too quickly.
        time.sleep(0.1)

    output = {
        "source": "OSV.dev",
        "unique_ids_requested": len(unique),
        "detailed_records_downloaded": len(detailed_records),
        "records": detailed_records,
    }

    OUTPUT_FILE.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    print("\nDownload complete!")
    print(f"Detailed records: {len(detailed_records)}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()