
from falkordb import FalkorDB

client = FalkorDB(host="localhost", port=6379)
graph = client.select_graph("traceops")

# These are demo application records, not real company infrastructure.
services = [
    {
        "name": "payment-api",
        "team": "payments-team",
        "repo": "payment-service",
        "package": "django",
        "version": "4.1.0",
        "ecosystem": "PyPI",
    },
    {
        "name": "customer-portal",
        "team": "web-team",
        "repo": "customer-portal",
        "package": "requests",
        "version": "2.28.0",
        "ecosystem": "PyPI",
    },
    {
        "name": "image-service",
        "team": "platform-team",
        "repo": "image-processing",
        "package": "pillow",
        "version": "9.0.0",
        "ecosystem": "PyPI",
    },
]

try:
    for item in services:
        # Create a service.
        graph.query(
            """
            MERGE (s:Service {name: $name})
            SET s.environment = 'demo'
            """,
            {"name": item["name"]},
        )

        # Create a repository.
        graph.query(
            """
            MERGE (r:Repository {name: $repo})
            SET r.environment = 'demo'
            """,
            {"repo": item["repo"]},
        )

        # Create an owning team.
        graph.query(
            """
            MERGE (t:Team {name: $team})
            """,
            {"team": item["team"]},
        )

        # Connect service, repository, and team.
        graph.query(
            """
            MATCH (s:Service {name: $name})
            MATCH (r:Repository {name: $repo})
            MATCH (t:Team {name: $team})
            MERGE (s)-[:DEPLOYED_FROM]->(r)
            MERGE (s)-[:OWNED_BY]->(t)
            """,
            {
                "name": item["name"],
                "repo": item["repo"],
                "team": item["team"],
            },
        )

        # Link the service to its package only if the package
        # already exists in the vulnerability graph.
        graph.query(
            """
            MATCH (s:Service {name: $service})
            MATCH (p:Package {
                key: $package_key
            })
            MERGE (s)-[d:DEPENDS_ON]->(p)
            SET d.declared_version = $version
            """,
            {
                "service": item["name"],
                "package_key": (
                    f'{item["ecosystem"].lower()}:'
                    f'{item["package"].lower()}'
                ),
                "version": item["version"],
            },
        )

    result = graph.query(
        """
        MATCH (s:Service)-[:DEPENDS_ON]->(p:Package)
        RETURN s.name, p.name, p.ecosystem
        ORDER BY s.name
        """
    )

    print("\n=== TraceOps Demo Environment ===")
    for row in result.result_set:
        print(f"Service: {row[0]} -> Package: {row[1]} ({row[2]})")

    print("\nDemo environment created successfully.")

finally:
    client.close()