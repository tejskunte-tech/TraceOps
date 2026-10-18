
from falkordb import FalkorDB

client = FalkorDB(host="localhost", port=6379)
graph = client.select_graph("traceops")

SERVICE_NAME = "payment-api"

try:
    result = graph.query(
        """
        MATCH (s:Service {name: $service})
              -[:DEPENDS_ON]->(p:Package)
              -[r:HAS_VULNERABILITY]->(v:Vulnerability)

        RETURN
            s.name AS service,
            p.name AS package,
            r.checked_version AS checked_version,
            v.id AS vulnerability_id,
            v.summary AS summary,
            v.severity AS severity

        ORDER BY p.name, v.id
        LIMIT 20
        """,
        {"service": SERVICE_NAME},
    )

    print(f"\n=== Investigation: {SERVICE_NAME} ===\n")

    if not result.result_set:
        print("No connected vulnerability records found.")
    else:
        for row in result.result_set:
            print(f"Service: {row[0]}")
            print(f"Package: {row[1]} {row[2]}")
            print(f"Advisory: {row[3]}")
            print(f"Description: {row[4]}")
            print(f"Severity: {row[5]}")
            print("-" * 50)

        print(f"\nRecords returned: {len(result.result_set)}")

finally:
    client.close()