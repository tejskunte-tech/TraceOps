
import json
from collections import Counter, defaultdict
from pathlib import Path

SOURCE = Path("data/raw/osv_detailed.json")
RESULTS = Path("data/validated_vulnerabilities.json")


def load_records(path):
    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return data.get("records", [])

    return data


def main():
    source_records = load_records(SOURCE)

    with RESULTS.open(encoding="utf-8") as f:
        results = json.load(f)

    by_package = defaultdict(Counter)

    for item in results:
        package = item.get("package", "UNKNOWN")
        status = item.get("version_status", "UNKNOWN")
        by_package[package][status] += 1

    print("\n===== RESULTS BY PACKAGE =====")

    for package, counts in sorted(by_package.items()):
        print(
            f"{package}: "
            f"AFFECTED={counts['AFFECTED']}, "
            f"NOT_AFFECTED={counts['NOT_AFFECTED']}, "
            f"UNKNOWN={counts['UNKNOWN']}"
        )

    print("\n===== NOT AFFECTED RECORDS =====")

    non_affected = [
        item for item in results
        if item.get("version_status") == "NOT_AFFECTED"
    ]

    if not non_affected:
        print("No NOT_AFFECTED records.")
    else:
        for item in non_affected:
            print(json.dumps(item, indent=2))

    print("\n===== RANGE FORMAT AUDIT =====")

    range_types = Counter()
    missing_ranges = []
    no_ecosystem_ranges = []

    for record in source_records:
        package = record.get("package_checked", {})
        vuln = record.get("vulnerability", {})
        all_ranges = []

        for affected in vuln.get("affected", []):
            affected_package = affected.get("package", {})

            if (
                affected_package.get("name", "").lower()
                != str(package.get("name", "")).lower()
                or affected_package.get("ecosystem")
                != package.get("ecosystem")
            ):
                continue

            all_ranges.extend(affected.get("ranges", []))

        if not all_ranges:
            missing_ranges.append(vuln.get("id", "UNKNOWN"))
            continue

        ecosystem_ranges = [
            r for r in all_ranges
            if r.get("type") == "ECOSYSTEM"
        ]

        if not ecosystem_ranges:
            no_ecosystem_ranges.append(
                vuln.get("id", "UNKNOWN")
            )

        for version_range in all_ranges:
            range_types[version_range.get("type", "MISSING")] += 1

    print("Range types:", dict(range_types))
    print("Records without matching ranges:", len(missing_ranges))
    print("Records without ECOSYSTEM ranges:", len(no_ecosystem_ranges))

    if missing_ranges:
        print("Missing range advisory IDs:", missing_ranges[:20])

    if no_ecosystem_ranges:
        print(
            "Non-ECOSYSTEM advisory IDs:",
            no_ecosystem_ranges[:20]
        )


if __name__ == "__main__":
    main()