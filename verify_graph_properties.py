
from falkordb import FalkorDB

def main():
    db = FalkorDB(host="localhost", port=6379)
    graph = db.select_graph("traceops")

    query = """
    MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
    RETURN
        p.name AS package,
        r.checked_version AS checked_version,
        v.id AS advisory,
        r.fixed_versions_json AS fixed_versions,
        r.source AS source
    LIMIT 10
    """

    result = graph.query(query)

    print("\n===== TraceOps Version Verification =====")

    if not result.result_set:
        print("No matching relationships found.")
        return

    for row in result.result_set:
        print({
            "package": row[0],
            "checked_version": row[1],
            "advisory": row[2],
            "fixed_versions": row[3],
            "source": row[4],
        })

if __name__ == "__main__":
    main()