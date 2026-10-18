
import json
from pathlib import Path
from falkordb import FalkorDB

DATA_FILE = Path("data/validated_vulnerabilities.json")

HOST = "localhost"
PORT = 6379
GRAPH_NAME = "traceops"


def main():
    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Missing validation file: {DATA_FILE}"
        )

    with DATA_FILE.open(encoding="utf-8") as file:
        records = json.load(file)

    db = FalkorDB(host=HOST, port=PORT)
    graph = db.select_graph(GRAPH_NAME)

    updated = 0
    missing = 0
    failed = 0

    query = """
    MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
    WHERE toLower(p.name) = toLower($package)
      AND p.ecosystem = $ecosystem
      AND r.checked_version = $installed_version
      AND v.id = $advisory
    SET r.version_status = $version_status,
        r.validation_reason = $validation_reason,
        r.validation_source = 'OSV.dev'
    RETURN count(r) AS updated
    """

    for item in records:
        params = {
            "package": item["package"],
            "ecosystem": item["ecosystem"],
            "installed_version": item["installed_version"],
            "advisory": item["advisory"],
            "version_status": item["version_status"],
            "validation_reason": item["validation_reason"],
        }

        try:
            result = graph.query(query, params)
            count = result.result_set[0][0]

            if count:
                updated += count
            else:
                missing += 1
                print(
                    "No matching relationship:",
                    item["package"],
                    item["installed_version"],
                    item["advisory"],
                )

        except Exception as exc:
            failed += 1
            print(
                "Update failed:",
                item["package"],
                item["advisory"],
                str(exc),
            )

    print("\n===== TraceOps Graph Validation Sync =====")
    print(f"Input records: {len(records)}")
    print(f"Relationships updated: {updated}")
    print(f"Records without matching relationships: {missing}")
    print(f"Failed updates: {failed}")


if __name__ == "__main__":
    main()