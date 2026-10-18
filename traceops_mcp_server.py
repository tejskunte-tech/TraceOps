#!/usr/bin/env python3
"""
TraceOps MCP Server
Graph-powered security investigation tools for the agent.
Uses FalkorDB as the core connected-data store.
"""

from __future__ import annotations

import json
from typing import Any

from falkordb import FalkorDB
from mcp.server.mcpserver import MCPServer

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HOST = "localhost"
PORT = 6379
GRAPH_NAME = "traceops"

mcp = MCPServer(
    name="TraceOps",
    title="TraceOps Security Investigation Agent",
    description=(
        "Graph-powered tools that investigate software security risks using "
        "FalkorDB. Supports multi-hop reasoning, risk prioritization, and "
        "explainable evidence for vulnerability triage and remediation."
    ),
)


def get_graph():
    """Return a live FalkorDB graph handle."""
    client = FalkorDB(host=HOST, port=PORT)
    return client.select_graph(GRAPH_NAME)


def _safe_json(val: Any) -> Any:
    """Parse JSON strings that may live in graph properties."""
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


# ---------------------------------------------------------------------------
# Tool 1 – list_packages
# ---------------------------------------------------------------------------
@mcp.tool()
def list_packages() -> dict:
    """
    List every package currently stored in the TraceOps graph.
    Returns package name, ecosystem and internal key.
    Use this as the first step when the user asks about their project packages.
    """
    graph = get_graph()
    result = graph.query(
        """
        MATCH (p:Package)
        RETURN p.name AS name, p.ecosystem AS ecosystem, p.key AS key
        ORDER BY p.name
        """
    )
    packages = [
        {"name": row[0], "ecosystem": row[1], "key": row[2]}
        for row in result.result_set
    ]
    return {"count": len(packages), "packages": packages}


# ---------------------------------------------------------------------------
# Tool 2 – list_vulnerabilities_for_package
# ---------------------------------------------------------------------------
@mcp.tool()
def list_vulnerabilities_for_package(package_name: str) -> dict:
    """
    Return all vulnerabilities connected to a package together with
    validation status and evidence. Performs a 1-hop graph traversal
    (Package → HAS_VULNERABILITY → Vulnerability).
    """
    graph = get_graph()
    result = graph.query(
        """
        MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE toLower(p.name) = toLower($name)
        RETURN
            p.name AS package,
            p.ecosystem AS ecosystem,
            r.checked_version AS checked_version,
            v.id AS advisory_id,
            v.summary AS summary,
            v.severity AS severity,
            r.version_status AS version_status,
            r.validation_reason AS validation_reason,
            r.fixed_versions_json AS fixed_versions,
            v.source_url AS source_url
        ORDER BY
            CASE r.version_status
                WHEN 'AFFECTED' THEN 0
                WHEN 'UNKNOWN'  THEN 1
                ELSE 2
            END,
            v.severity DESC
        """,
        {"name": package_name},
    )

    findings = []
    for row in result.result_set:
        findings.append(
            {
                "package": row[0],
                "ecosystem": row[1],
                "checked_version": row[2],
                "advisory_id": row[3],
                "summary": row[4],
                "severity": row[5] or "UNKNOWN",
                "version_status": row[6] or "MISSING",
                "validation_reason": row[7],
                "fixed_versions": _safe_json(row[8]),
                "source_url": row[9],
            }
        )

    return {
        "package": package_name,
        "finding_count": len(findings),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Tool 3 – investigate_advisory
# ---------------------------------------------------------------------------
@mcp.tool()
def investigate_advisory(advisory_id: str) -> dict:
    """
    Deep-dive a single advisory. Returns the full evidence chain:
    Package ← relationship properties ← Vulnerability.
    Explicitly surfaces conflicting or UNKNOWN validation results.
    """
    graph = get_graph()
    result = graph.query(
        """
        MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE v.id = $id
        RETURN
            v.id AS advisory_id,
            v.summary AS summary,
            v.details AS details,
            v.severity AS severity,
            v.published AS published,
            v.aliases_json AS aliases,
            v.references_json AS references,
            v.source_url AS source_url,
            p.name AS package,
            p.ecosystem AS ecosystem,
            r.checked_version AS checked_version,
            r.version_status AS version_status,
            r.validation_reason AS validation_reason,
            r.fixed_versions_json AS fixed_versions,
            r.source AS relationship_source
        """,
        {"id": advisory_id},
    )

    if not result.result_set:
        return {
            "found": False,
            "advisory_id": advisory_id,
            "message": "No matching advisory found in the graph.",
        }

    row = result.result_set[0]
    status = row[11] or "MISSING"
    evidence_note = None
    if status == "UNKNOWN":
        evidence_note = (
            "Validation could not determine impact with high confidence. "
            "This may be caused by conflicting range data or unsupported "
            "range types (e.g. Git commit ranges). Treat as requiring human review."
        )

    return {
        "found": True,
        "advisory_id": row[0],
        "summary": row[1],
        "details": (row[2] or "")[:800],
        "severity": row[3] or "UNKNOWN",
        "published": row[4],
        "aliases": _safe_json(row[5]),
        "references": _safe_json(row[6]),
        "source_url": row[7],
        "package": row[8],
        "ecosystem": row[9],
        "checked_version": row[10],
        "version_status": status,
        "validation_reason": row[12],
        "fixed_versions": _safe_json(row[13]),
        "relationship_source": row[14],
        "evidence_note": evidence_note,
    }


# ---------------------------------------------------------------------------
# Tool 4 – get_package_risk_summary
# ---------------------------------------------------------------------------
@mcp.tool()
def get_package_risk_summary(package_name: str) -> dict:
    """
    Produce a prioritised risk summary for a package.
    Counts AFFECTED / UNKNOWN / NOT_AFFECTED findings and surfaces the
    highest-priority items that need action first.
    This is the main tool an agent should call when asked
    'what should I fix first?'.
    """
    graph = get_graph()
    result = graph.query(
        """
        MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE toLower(p.name) = toLower($name)
        RETURN
            r.version_status AS status,
            v.id AS advisory_id,
            v.severity AS severity,
            v.summary AS summary,
            r.checked_version AS checked_version,
            r.fixed_versions_json AS fixed_versions,
            r.validation_reason AS reason
        """,
        {"name": package_name},
    )

    counts = {"AFFECTED": 0, "UNKNOWN": 0, "NOT_AFFECTED": 0, "MISSING": 0}
    priority = []  # AFFECTED first, then UNKNOWN

    for row in result.result_set:
        status = row[0] or "MISSING"
        counts[status] = counts.get(status, 0) + 1
        if status in ("AFFECTED", "UNKNOWN"):
            priority.append(
                {
                    "priority": "HIGH" if status == "AFFECTED" else "REVIEW",
                    "advisory_id": row[1],
                    "severity": row[2] or "UNKNOWN",
                    "summary": row[3],
                    "checked_version": row[4],
                    "fixed_versions": _safe_json(row[5]),
                    "status": status,
                    "reason": row[6],
                }
            )

    # simple ordering: AFFECTED before UNKNOWN, then by severity if present
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}
    priority.sort(
        key=lambda x: (
            0 if x["status"] == "AFFECTED" else 1,
            severity_rank.get(str(x["severity"]).upper(), 9),
        )
    )

    recommendation = (
        "Immediate action required on confirmed AFFECTED findings."
        if counts["AFFECTED"]
        else "No confirmed affected findings. Review UNKNOWN items carefully."
        if counts["UNKNOWN"]
        else "No actionable findings for this package."
    )

    return {
        "package": package_name,
        "counts": counts,
        "priority_findings": priority[:10],  # keep payload small
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Tool 5 – multi_hop_investigation (core for the track)
# ---------------------------------------------------------------------------
@mcp.tool()
def multi_hop_investigation(package_name: str, max_hops: int = 2) -> dict:
    """
    Perform multi-hop graph reasoning starting from a package.
    Path: Package -[:HAS_VULNERABILITY]-> Vulnerability
          and returns the full evidence path so the agent can explain
          every hop. Designed to satisfy the 'multi-hop reasoning'
          and 'graph queries as agent tools' requirements of the track.
    """
    graph = get_graph()

    # Hop 1 + 2 in one Cypher query (Package → Vuln → related packages sharing same vuln)
    result = graph.query(
        """
        MATCH path = (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE toLower(p.name) = toLower($name)
        OPTIONAL MATCH (other:Package)-[r2:HAS_VULNERABILITY]->(v)
        WHERE other.name <> p.name
        RETURN
            p.name AS start_package,
            r.checked_version AS start_version,
            r.version_status AS start_status,
            v.id AS advisory_id,
            v.severity AS severity,
            v.summary AS summary,
            collect(DISTINCT other.name) AS also_affected_packages,
            r.validation_reason AS reason,
            r.fixed_versions_json AS fixed_versions
        LIMIT 20
        """,
        {"name": package_name},
    )

    paths = []
    for row in result.result_set:
        paths.append(
            {
                "path": [
                    {"type": "Package", "name": row[0], "version": row[1], "status": row[2]},
                    {"type": "HAS_VULNERABILITY", "status": row[2]},
                    {
                        "type": "Vulnerability",
                        "id": row[3],
                        "severity": row[4],
                        "summary": row[5],
                    },
                ],
                "also_affected_packages": row[6] or [],
                "validation_reason": row[7],
                "fixed_versions": _safe_json(row[8]),
                "hop_count": 2 if row[6] else 1,
            }
        )

    return {
        "start_package": package_name,
        "paths_found": len(paths),
        "investigation_paths": paths,
        "explanation": (
            "Each path shows the concrete graph traversal the agent used. "
            "also_affected_packages demonstrates a second hop through the "
            "shared Vulnerability node."
        ),
    }


# ---------------------------------------------------------------------------
# Tool 6 – list_unknown_or_conflicting (explainability helper)
# ---------------------------------------------------------------------------
@mcp.tool()
def list_unknown_or_conflicting() -> dict:
    """
    Surface every finding whose version_status is UNKNOWN or missing.
    Critical for explainable results – the agent must never hide uncertainty.
    """
    graph = get_graph()
    result = graph.query(
        """
        MATCH (p:Package)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE r.version_status IS NULL
           OR r.version_status = 'UNKNOWN'
           OR r.version_status = 'MISSING'
        RETURN
            p.name AS package,
            r.checked_version AS version,
            v.id AS advisory_id,
            r.version_status AS status,
            r.validation_reason AS reason
        ORDER BY package
        """
    )
    items = [
        {
            "package": row[0],
            "version": row[1],
            "advisory_id": row[2],
            "status": row[3] or "MISSING",
            "reason": row[4],
        }
        for row in result.result_set
    ]
    return {"unknown_count": len(items), "items": items}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # stdio is the standard transport for MCP agents / Cursor / Claude Desktop
    mcp.run(transport="stdio")