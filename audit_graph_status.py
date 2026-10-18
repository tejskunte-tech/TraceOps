import json
from pathlib import Path
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("traceops")

query = """
MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN
p.name AS package,
r.checked_version AS installed_version,
v.id AS advisory,
r.version_status AS status,
r.validation_reason AS reason
ORDER BY package, advisory
"""

result = graph.query(query)

counts = {}
rows = result.result_set

for row in rows:
    package, version, advisory, status, reason = row
    status = status or "MISSING"
    counts[status] = counts.get(status, 0) + 1

print("\n===== GRAPH STATUS AUDIT =====")
print("Relationships inspected:", len(rows))

for status, count in sorted(counts.items()):
    print(f"{status}: {count}")

print("\n===== UNKNOWN OR MISSING STATUS =====")
for row in rows:
    package, version, advisory, status, reason = row
    if status in (None, "UNKNOWN") or status is None:
        print({
        "package": package,
        "version": version,
        "advisory": advisory,
        "status": status,
        "reason": reason,
        })
