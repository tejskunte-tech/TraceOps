
from falkordb import FalkorDB

client = FalkorDB(host="localhost", port=6379)
graph = client.select_graph("traceops")

try:
    result = graph.query("""
        MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN
            p.name AS package,
            r.checked_version AS version,
            v.id AS vulnerability,
            v.summary AS description
        ORDER BY p.name
        LIMIT 15
    """)

    print("\n=== TraceOps Security Investigation ===\n")

    for row in result.result_set:
        print(f"Package: {row[0]} version {row[1]}")
        print(f"Vulnerability: {row[2]}")
        print(f"Description: {row[3]}")
        print("-" * 50)

finally:
    client.close()
    