# TraceOps

**Graph-powered security investigation agent.** Investigate vulnerabilities, explain the evidence, prioritize the fix.

> Built for **FalkorDB Graph Hacks: Context for AI Agents**
> **Track: Agents That Act on Connected Data**

---

## The problem

A vulnerability alert tells you *what* is wrong. It does not tell you which package to fix first, what evidence supports that, or what exact version to upgrade to. TraceOps answers those three questions by letting an agent walk a graph of packages and advisories instead of reading a flat list.

## What it does

1. **Ingest**: upload a `requirements.txt`. TraceOps queries [OSV.dev](https://osv.dev) (public data) and loads packages, advisories, and their relationships into FalkorDB.
2. **Investigate**: ask a question in plain English. A Gemini agent picks from 8 MCP tools, calls them, and reads the results.
3. **Act**: the agent returns a risk ranking, graph evidence paths, uncertain findings, and a concrete `pip install` upgrade command taken from the fixed versions stored on the graph edges.

**Security boundary:** the model never writes Cypher. It can only call named MCP tools, and every database access goes through parameterized queries inside those tools.

## Architecture

```
Streamlit UI (app.py)  or  CLI
        │
        ▼
traceops_agent.py        Gemini tool-calling loop (max 15 tool rounds)
        │  MCP (stdio)
        ▼
traceops_mcp_server.py   8 tools, each wrapping a Cypher query
        │  Cypher
        ▼
FalkorDB  (graph: traceops)
        ▲
ingest_from_requirements.py   requirements.txt → OSV.dev → graph
```

## Graph data model

```
(:Package {key, name, ecosystem})
    -[:HAS_VULNERABILITY {
        checked_version,      // version from the user's requirements.txt
        version_status,       // AFFECTED | UNKNOWN | MISSING
        validation_reason,
        fixed_versions_json,  // fixed versions from the OSV advisory
        source                // 'OSV.dev'
    }]->
(:Vulnerability {
    id, summary, details, severity,
    published, modified,
    aliases_json, references_json, source_url
})
```

Two packages that share an advisory are connected through the same `Vulnerability` node. That shared node is what the multi-hop tool follows.

## Cypher the product depends on

**Ingestion** (`ingest_from_requirements.py`)

```cypher
MERGE (p:Package {key: $key}) SET p.name = $name, p.ecosystem = $ecosystem

MERGE (v:Vulnerability {id: $id}) SET v.summary = $summary, v.severity = $severity, ...

MATCH (p:Package {key: $key}), (v:Vulnerability {id: $id})
MERGE (p)-[r:HAS_VULNERABILITY]->(v)
SET r.checked_version = $version, r.fixed_versions_json = $fixed,
    r.source = 'OSV.dev', r.version_status = 'AFFECTED'
```

**Multi-hop investigation** (`multi_hop_investigation`): package → advisory → *other* packages hit by the same advisory

```cypher
MATCH path = (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE toLower(p.name) = toLower($name)
OPTIONAL MATCH (other:Package)-[r2:HAS_VULNERABILITY]->(v)
WHERE other.name <> p.name
RETURN p.name, r.checked_version, r.version_status, v.id, v.severity, v.summary,
       collect(DISTINCT other.name) AS also_affected_packages,
       r.validation_reason, r.fixed_versions_json
LIMIT 20
```

**Risk ranking** (`rank_packages_by_risk`): degree-based ranking over confirmed `AFFECTED` edges

```cypher
MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE r.version_status = 'AFFECTED'
RETURN p.name, p.ecosystem, count(r) AS affected_count, collect(DISTINCT v.severity)
ORDER BY affected_count DESC
```

**Uncertain findings** (`list_unknown_or_conflicting`)

```cypher
MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE r.version_status IS NULL OR r.version_status IN ['UNKNOWN', 'MISSING']
RETURN p.name, r.checked_version, v.id, r.version_status, r.validation_reason
```

**Remediation** (`recommend_remediation`): upgrade targets read from the edge

```cypher
MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE toLower(p.name) = toLower($name) AND r.version_status = 'AFFECTED'
RETURN p.name, r.checked_version, v.id, v.severity, r.fixed_versions_json
```

The remaining tools (`list_packages`, `list_vulnerabilities_for_package`, `investigate_advisory`, `get_package_risk_summary`) are 1-hop lookups over the same pattern. All queries live in `traceops_mcp_server.py`.

## MCP tools

| Tool | Purpose |
|---|---|
| `list_packages` | List packages in the graph |
| `list_vulnerabilities_for_package` | 1-hop advisories for a package |
| `investigate_advisory` | Deep dive on one advisory |
| `get_package_risk_summary` | Prioritized summary for a package |
| `multi_hop_investigation` | Package → advisory → other affected packages |
| `list_unknown_or_conflicting` | Surface uncertain findings |
| `rank_packages_by_risk` | Rank packages by confirmed affected edges |
| `recommend_remediation` | Upgrade command from fixed versions on the graph |

## Run locally

Prerequisites: Python 3.11+, Docker, a [Gemini API key](https://aistudio.google.com/).

```bash
# 1. Start FalkorDB (browser UI on http://localhost:3000)
docker run -p 6379:6379 -p 3000:3000 --rm falkordb/falkordb:latest

# 2. Install
git clone <YOUR-REPO-URL> && cd Traceops
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure
echo "GEMINI_API_KEY=your-key-here" > .env     # never commit this file

# 4. Load data from the demo file
python ingest_from_requirements.py requirements-demo.txt

# 5a. Web UI
streamlit run app.py
# 5b. or CLI
python traceops_agent.py "Which packages have the highest risk and what should I fix first?"
```

To inspect the graph, open http://localhost:3000 and run `MATCH (p:Package)-[r]->(v) RETURN p, r, v LIMIT 50`.

## Example run

Demo input: `requirements-demo.txt` (deliberately pinned to older versions so OSV returns real findings).
Question: *"Rank the packages by their number of associated affected vulnerability findings, and show the evidence behind the ranking."*

| Rank | Package | Affected findings |
|---|---|---|
| 1 | aiohttp | 85 |
| 2 | pillow | 37 |
| 3 | django | 26 |
| 4 | urllib3 | 20 |

For each package the agent also returns graph paths such as `pillow → HAS_VULNERABILITY → GHSA-…` with the fixed version, and a `pip install` command.

## Data

Vulnerability data comes from the public [OSV.dev](https://osv.dev) API. The demo `requirements` file is synthetic. No private or restricted data is loaded.

## Limitations (honest notes)

- The graph is currently package ↔ advisory. It does not yet model package-to-package dependencies, so "blast radius through transitive dependencies" is future work.
- The ranking is a degree count over `AFFECTED` edges computed in Cypher, not a FalkorDB built-in algorithm.
- `multi_hop_investigation` follows one shared-advisory hop; the `max_hops` argument is reserved and not yet used.
- The live ingestion path marks OSV results as `AFFECTED` because OSV already filters by version, so `UNKNOWN` findings appear mainly when validation data is added.

## AI-use disclosure

- **Runtime:** Gemini (`gemini-3.1-flash-lite`) is the agent model.
- **Development:** Gemini, for drafting the project description, structuring technical feedback responses, and refining documentation.

