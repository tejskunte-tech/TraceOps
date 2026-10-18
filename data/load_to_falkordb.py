
import json
from pathlib import Path
from falkordb import FalkorDB

DATA_DIR = Path(__file__).resolve().parent
INPUT_FILE = DATA_DIR / "raw" / "osv_detailed.json"

HOST = "localhost"
PORT = 6379
GRAPH_NAME = "traceops"


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"File not found: {INPUT_FILE}")

    data = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

    client = FalkorDB(host=HOST, port=PORT)
    graph = client.select_graph(GRAPH_NAME)

    try:
        graph.query("RETURN 1")
        print(f"Connected to FalkorDB graph: {GRAPH_NAME}")

        loaded = 0
        skipped = 0

        for record in data.get("records", []):
            checked = record.get("package_checked", {})
            vuln = record.get("vulnerability", {})

            name = checked.get("name")
            ecosystem = checked.get("ecosystem")
            version = checked.get("version")
            vuln_id = vuln.get("id")

            if not all([name, ecosystem, version, vuln_id]):
                skipped += 1
                continue

            # Verify the advisory identifies this same package.
            affected_entries = [
                item for item in vuln.get("affected", [])
                if item.get("package", {}).get("name", "").lower()
                == name.lower()
                and item.get("package", {}).get("ecosystem", "").lower()
                == ecosystem.lower()
            ]

            if not affected_entries:
                skipped += 1
                continue

            # Keep fixed versions from matching advisory entries.
            fixed_versions = sorted({
                event["fixed"]
                for item in affected_entries
                for version_range in item.get("ranges", [])
                for event in version_range.get("events", [])
                if event.get("fixed")
            })

            severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN")

            package_key = f"{ecosystem.lower()}:{name.lower()}"

            # Create or update the Package node.
            graph.query(
                """
                MERGE (p:Package {key: $key})
                SET p.name = $name,
                    p.ecosystem = $ecosystem
                """,
                {
                    "key": package_key,
                    "name": name,
                    "ecosystem": ecosystem,
                },
            )

            # Create or update the Vulnerability node.
            graph.query(
                """
                MERGE (v:Vulnerability {id: $id})
                SET v.summary = $summary,
                    v.details = $details,
                    v.severity = $severity,
                    v.published = $published,
                    v.modified = $modified,
                    v.aliases_json = $aliases,
                    v.references_json = $references,
                    v.source_url = $source_url
                """,
                {
                    "id": vuln_id,
                    "summary": vuln.get("summary", ""),
                    "details": vuln.get("details", ""),
                    "severity": severity,
                    "published": vuln.get("published", ""),
                    "modified": vuln.get("modified", ""),
                    "aliases": json.dumps(vuln.get("aliases", [])),
                    "references": json.dumps(vuln.get("references", [])),
                    "source_url": record.get("source_url", ""),
                },
            )

            # Connect the package and vulnerability.
            graph.query(
                """
                MATCH (p:Package {key: $key})
                MATCH (v:Vulnerability {id: $id})
                MERGE (p)-[r:HAS_VULNERABILITY]->(v)
                SET r.checked_version = $version,
                    r.fixed_versions_json = $fixed_versions,
                    r.source = 'OSV.dev'
                """,
                {
                    "key": package_key,
                    "id": vuln_id,
                    "version": version,
                    "fixed_versions": json.dumps(fixed_versions),
                },
            )

            loaded += 1

        # Verify the graph's actual contents.
        packages = graph.query(
            "MATCH (p:Package) RETURN count(p)"
        ).result_set[0][0]

        vulnerabilities = graph.query(
            "MATCH (v:Vulnerability) RETURN count(v)"
        ).result_set[0][0]

        relationships = graph.query(
            """
            MATCH (:Package)-[r:HAS_VULNERABILITY]->(:Vulnerability)
            RETURN count(r)
            """
        ).result_set[0][0]

        print("\n===== TraceOps Results =====")
        print(f"Records loaded: {loaded}")
        print(f"Records skipped: {skipped}")
        print(f"Package nodes: {packages}")
        print(f"Vulnerability nodes: {vulnerabilities}")
        print(f"Relationships: {relationships}")

        print("\nSample connections:")
        sample = graph.query(
            """
            MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN p.name, r.checked_version, v.id, v.summary
            LIMIT 5
            """
        )

        for row in sample.result_set:
            print(row)

    finally:
        client.close()


if __name__ == "__main__":
    main()