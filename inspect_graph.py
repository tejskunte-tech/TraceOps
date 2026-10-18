
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("traceops")

queries = {
    "Packages": """
        MATCH (p:Package)
        RETURN properties(p)
        LIMIT 10
    """,
    "Vulnerabilities": """
        MATCH (v:Vulnerability)
        RETURN properties(v)
        LIMIT 3
    """,
    "Relationships": """
        MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN properties(p), properties(r), properties(v)
        LIMIT 3
    """,
}

for title, query in queries.items():
    print(f"\n===== {title} =====")
    result = graph.query(query)

    for row in result.result_set:
        print(row)