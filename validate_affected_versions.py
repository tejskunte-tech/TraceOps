
import json
from pathlib import Path
from packaging.version import Version, InvalidVersion

INPUT_FILE = Path("data/raw/osv_detailed.json")
OUTPUT_FILE = Path("data/validated_vulnerabilities.json")


def version_matches(installed, events):
    """
    Return:
        True  -> installed version is in an evaluated affected range
        False -> installed version is outside a fully evaluated range
        None  -> range cannot be evaluated reliably
    """
    try:
        version = Version(str(installed))

        if not events:
            return None

        introduced = None
        has_introduction = False
        evaluated = False

        for event in events:
            if "introduced" in event:
                value = str(event["introduced"])

                if value == "0":
                    introduced = None
                else:
                    introduced = Version(value)

                has_introduction = True

            elif "fixed" in event:
                fixed = Version(str(event["fixed"]))

                if not has_introduction:
                    return None

                lower_ok = (
                    introduced is None or version >= introduced
                )
                evaluated = True

                if lower_ok and version < fixed:
                    return True

                introduced = None
                has_introduction = False

            elif "last_affected" in event:
                last = Version(str(event["last_affected"]))

                if not has_introduction:
                    return None

                lower_ok = (
                    introduced is None or version >= introduced
                )
                evaluated = True

                if lower_ok and version <= last:
                    return True

                introduced = None
                has_introduction = False

            elif "limit" in event:
                return None

            else:
                return None

        # An open-ended introduced range includes later versions.
        if has_introduction:
            lower_ok = (
                introduced is None or version >= introduced
            )

            if lower_ok:
                return True

            evaluated = True

        return False if evaluated else None

    except (InvalidVersion, TypeError, ValueError):
        return None


def check_record(record):
    package = record.get("package_checked", {})
    vulnerability = record.get("vulnerability", {})

    name = package.get("name")
    ecosystem = package.get("ecosystem")
    installed = package.get("version")
    vuln_id = vulnerability.get("id")

    ecosystem_results = []
    matching_package_found = False
    range_types_seen = set()
    unsupported_range_types = set()

    for affected in vulnerability.get("affected", []):
        affected_package = affected.get("package", {})

        if (
            str(affected_package.get("name", "")).lower()
            != str(name).lower()
            or affected_package.get("ecosystem") != ecosystem
        ):
            continue

        matching_package_found = True

        for version_range in affected.get("ranges", []):
            range_type = version_range.get("type", "UNKNOWN")
            range_types_seen.add(range_type)

            # This validator does not interpret Git commit ranges.
            if range_type != "ECOSYSTEM":
                unsupported_range_types.add(range_type)
                continue

            if ecosystem != "PyPI":
                unsupported_range_types.add(range_type)
                continue

            ecosystem_results.append(
                version_matches(
                    installed,
                    version_range.get("events", [])
                )
            )

    if not matching_package_found or not ecosystem_results:
        status = "UNKNOWN"
        reason = (
            "No evaluable ecosystem range was found "
            "for the matching package."
        )

    elif any(result is True for result in ecosystem_results):
        status = "AFFECTED"
        reason = (
            "At least one evaluated ecosystem range confirms "
            "the installed version is affected."
        )

    elif any(result is None for result in ecosystem_results):
        status = "UNKNOWN"
        reason = (
            "At least one ecosystem range could not be evaluated "
            "reliably."
        )

    elif unsupported_range_types:
        status = "UNKNOWN"
        reason = (
            "Evaluated ecosystem ranges exclude the installed version, "
            "but unsupported range types prevent a confident conclusion."
        )

    else:
        status = "NOT_AFFECTED"
        reason = (
            "All matching ecosystem ranges were evaluated and "
            "exclude the installed version."
        )

    return {
        "package": name,
        "ecosystem": ecosystem,
        "installed_version": installed,
        "advisory": vuln_id,
        "summary": vulnerability.get("summary", ""),
        "version_status": status,
        "validation_reason": reason,
        "range_types": sorted(range_types_seen),
        "unsupported_range_types": sorted(unsupported_range_types),
        "source_url": record.get("source_url", ""),
    }


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Missing {INPUT_FILE}. Check the filename and folder."
        )

    with INPUT_FILE.open(encoding="utf-8") as file:
        data = json.load(file)

    records = (
        data.get("records", [])
        if isinstance(data, dict)
        else data
    )

    results = [check_record(record) for record in records]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2, ensure_ascii=False)

    print("\n===== TraceOps Version Validation =====")
    print(f"Records checked: {len(results)}")

    for status in ("AFFECTED", "NOT_AFFECTED", "UNKNOWN"):
        count = sum(
            item["version_status"] == status
            for item in results
        )
        print(f"{status}: {count}")

    unsupported_count = sum(
        bool(item["unsupported_range_types"])
        for item in results
    )
    print(f"Records with unsupported ranges: {unsupported_count}")

    print(f"\nSaved results to: {OUTPUT_FILE}")

    print("\nSample results:")
    for item in results[:10]:
        print(
            f"{item['package']} {item['installed_version']} "
            f"{item['advisory']} -> {item['version_status']}"
        )
        print(f"  Reason: {item['validation_reason']}")


if __name__ == "__main__":
    main()