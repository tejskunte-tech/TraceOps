
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("traceops")

query = """
MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN p.name AS package,
       r.checked_version AS installed_version,
       v.id AS advisory,
       r.version_status AS status,
       r.validation_reason AS reason
LIMIT 15
"""

result = graph.query(query)

print("\n===== TraceOps Validated Findings =====")

for row in result.result_set:
    print({
        "package": row[0],
        "installed_version": row[1],
        "advisory": row[2],
        "status": row[3],
        "reason": row[4],
    })