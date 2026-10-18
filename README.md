TraceOps

Graph-Powered Security Investigation Agent

TraceOps is an AI agent that uses FalkorDB as its connected-data layer to investigate software vulnerabilities, perform multi-hop reasoning, rank risk, and recommend concrete remediation actions.

Built for the FalkorDB Graph Hacks – Track 01: Agents That Act on Connected Data.



Track 01 Coverage







Requirement



How TraceOps satisfies it





Multi-hop reasoning



multi_hop_investigation tool follows Package → Vulnerability → other affected packages





Graph queries & algorithms as agent tools



Multiple Cypher tools + Degree Centrality ranking (rank_packages_by_risk)





Tool selection through MCP



Full MCP server. The agent dynamically discovers and selects tools





Actions based on what the graph shows



recommend_remediation returns concrete upgrade commands grounded in fixed versions from the graph





Explainable results



Every answer includes evidence paths, version status (AFFECTED / UNKNOWN), and the tools used



Architecture

User Query
    │
    ▼
traceops_agent.py          ← Gemini agent (tool-calling loop)
    │
    │  MCP (stdio)
    ▼
traceops_mcp_server.py     ← MCP Server (8 tools)
    │
    │  Cypher
    ▼
FalkorDB (graph: traceops)
    │
    ├── (:Package)
    └── [:HAS_VULNERABILITY] → (:Vulnerability)

The agent never writes raw Cypher. It only calls well-defined MCP tools. The graph is the single source of truth for all decisions.



Features





Live ingestion from any requirements.txt



Multi-hop graph investigation



Degree Centrality risk ranking



Dynamic remediation recommendations (pip install package>=version)



Explicit handling of UNKNOWN / conflicting findings



Fully explainable evidence paths



Quick Start

1. Prerequisites





Python 3.11+



Docker (for FalkorDB)



Gemini API key

2. Start FalkorDB

docker run -p 6379:6379 -p 3000:3000 --rm falkordb/falkordb:latest

3. Setup

git clone <your-repo-url>
cd Traceops

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt

4. Add your Gemini API key

Create a .env file:

GEMINI_API_KEY=your-key-here

5. Load data

# Using the sample file
python ingest_from_requirements.py requirements-sample.txt

# Or your own requirements.txt
python ingest_from_requirements.py path/to/requirements.txt

6. Run the agent

python traceops_agent.py

Or with a specific question:

python traceops_agent.py "Which packages have the highest risk and what should I fix first?"



Available MCP Tools







Tool



Purpose





list_packages



List all packages in the graph





list_vulnerabilities_for_package



1-hop vulnerabilities for a package





investigate_advisory



Deep dive into a single advisory





get_package_risk_summary



Prioritized risk summary





multi_hop_investigation



Multi-hop path exploration





list_unknown_or_conflicting



Surface uncertain findings





rank_packages_by_risk



Degree Centrality ranking





recommend_remediation



Concrete upgrade command



Example Agent Flow

User: Investigate security risks and tell me what to fix first

Agent:
  → list_packages()
  → rank_packages_by_risk()
  → multi_hop_investigation("pillow")
  → recommend_remediation("pillow")
  → get_package_risk_summary("django")
  ...

Final Report:
  1. pillow  → 43 AFFECTED  →  pip install pillow>=10.3.0
  2. django  → 32 AFFECTED  →  pip install django>=4.2.26
  ...



Project Structure

Traceops/
├── traceops_mcp_server.py      # MCP server + all graph tools
├── traceops_agent.py           # Gemini agent with MCP tool loop
├── ingest_from_requirements.py # Live OSV ingestion
├── requirements.txt
├── requirements-sample.txt
├── .env                        # GEMINI_API_KEY (not committed)
├── data/
│   └── raw/
└── README.md



Graph Data Model

(:Package {key, name, ecosystem})
    -[:HAS_VULNERABILITY {
        checked_version,
        version_status,      // AFFECTED | UNKNOWN | ...
        validation_reason,
        fixed_versions_json,
        source
    }]->
(:Vulnerability {
    id, summary, details, severity,
    published, modified,
    aliases_json, references_json, source_url
})



Why FalkorDB?





Fast multi-hop Cypher queries



Perfect fit for agent tool calling



Simple local setup with Docker



Native support for the algorithms we expose as tools



License

MIT