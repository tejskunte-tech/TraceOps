
import json
from pathlib import Path
from falkordb import FalkorDB

RESULTS_FILE = Path("data/version_check_results.json")
GRAPH_NAME = "traceops"

def main():
    if not RESULTS_FILE.exists():
        raise FileNotFoundError(
            f"Results file not found: {RESULTS_FILE}"
        )

    with RESULTS_FILE.open("r", encoding="utf-8") as file:
        results = json.load(file)

    client = FalkorDB(host="localhost", port=6379)

    try:
        graph = client.select_graph(GRAPH_NAME)

        updated = 0
        missing = 0

        for item in results:
            package = item["package"]
            package_name = package["name"]
            version = package["version"]
            ecosystem = package["ecosystem"]

            for advisory in item.get("advisories", []):
                advisory_id = advisory.get("id")

                if not advisory_id:
                    continue

                # Update only an existing package-to-advisory
                # relationship. Do not create unverified links.
                query = """
                MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE toLower(p.name) = toLower($package_name)
                  AND p.version = $version
                  AND p.ecosystem = $ecosystem
                  AND v.id = $advisory_id
                SET r.osv_version_match = true,
                    r.checked_version = $version,
                    r.verification_source = 'OSV.dev',
                    r.verified_at = $checked_at,
                    v.source_url = $source_url
                RETURN v.id
                """

                response = graph.query(
                    query,
                    {
                        "package_name": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "advisory_id": advisory_id,
                        "checked_at": item.get("checked_at", ""),
                        "source_url": advisory.get("source_url", ""),
                    },
                )

                if response.result_set:
                    updated += 1
                else:
                    missing += 1
                    print(
                        "No existing graph relationship:",
                        package_name,
                        version,
                        advisory_id,
                    )

        print("\n=== TraceOps Graph Update ===")
        print("Existing relationships updated:", updated)
        print("Relationships not found:", missing)

    finally:
        client.close()


if __name__ == "__main__":
    main()