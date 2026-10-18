#!/usr/bin/env python3
"""
TraceOps – Live Ingestion from requirements.txt

Reads a requirements.txt, queries OSV for each package+version,
then upserts the results into the FalkorDB graph.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import requests
from falkordb import FalkorDB
from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HOST = "localhost"
PORT = 6379
GRAPH_NAME = "traceops"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_DIR = DATA_DIR / "raw"

# Simple regex fallback for lines that packaging cannot parse
REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*([=<>!~]+)\s*([A-Za-z0-9_.+-]+)"
)


def parse_requirements(path: Path) -> list[dict[str, str]]:
    """Return list of {name, version, ecosystem} from a requirements file."""
    packages = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Try proper parser first
        try:
            req = Requirement(line)
            name = req.name
            # Take the first specifier that has an exact version
            version = None
            for spec in req.specifier:
                if spec.operator in ("==", "==="):
                    version = spec.version
                    break
            if version is None and req.specifier:
                # fallback: take the version part of the first specifier
                version = str(list(req.specifier)[0]).lstrip("=<>!~")
            if not version:
                print(f"  skip (no version): {line}")
                continue
            packages.append(
                {"name": name, "version": version, "ecosystem": "PyPI"}
            )
            continue
        except Exception:
            pass

        # Regex fallback
        m = REQ_LINE_RE.match(line)
        if m:
            packages.append(
                {
                    "name": m.group(1),
                    "version": m.group(3),
                    "ecosystem": "PyPI",
                }
            )
        else:
            print(f"  skip (unparseable): {line}")

    return packages


def query_osv_batch(packages: list[dict]) -> list[dict]:
    """Call OSV querybatch and return list of {package, vulns}."""
    queries = [
        {
            "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
            "version": p["version"],
        }
        for p in packages
    ]
    resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=60)
    resp.raise_for_status()
    results = resp.json().get("results", [])

    out = []
    for pkg, result in zip(packages, results):
        vulns = result.get("vulns") or []
        out.append({"package": pkg, "vulns": vulns})
    return out


def fetch_vuln_details(vuln_id: str) -> dict[str, Any]:
    """Fetch full vulnerability details from OSV."""
    resp = requests.get(OSV_VULN_URL.format(id=vuln_id), timeout=30)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()


def upsert_to_graph(records: list[dict]) -> None:
    """Upsert packages, vulnerabilities and relationships into FalkorDB."""
    client = FalkorDB(host=HOST, port=PORT)
    graph = client.select_graph(GRAPH_NAME)

    loaded = 0
    for rec in records:
        pkg = rec["package"]
        vuln = rec["vulnerability"]

        name = pkg["name"]
        ecosystem = pkg["ecosystem"]
        version = pkg["version"]
        vuln_id = vuln.get("id")
        if not vuln_id:
            continue

        package_key = f"{ecosystem.lower()}:{name.lower()}"

        # Package node
        graph.query(
            """
            MERGE (p:Package {key: $key})
            SET p.name = $name,
                p.ecosystem = $ecosystem
            """,
            {"key": package_key, "name": name, "ecosystem": ecosystem},
        )

        # Vulnerability node
        severity = (
            vuln.get("database_specific", {}).get("severity")
            or (vuln.get("severity") or [{}])[0].get("type")
            or "UNKNOWN"
        )
        graph.query(
            """
            MERGE (v:Vulnerability {id: $id})
            SET v.summary = $summary,
                v.details = $details,
                v.severity = $severity,
                v.published = $published,
                v.modified = $modified,
                v.aliases_json = $aliases,
                v.references_json = $references,
                v.source_url = $source_url
            """,
            {
                "id": vuln_id,
                "summary": vuln.get("summary") or "",
                "details": (vuln.get("details") or "")[:2000],
                "severity": severity,
                "published": vuln.get("published") or "",
                "modified": vuln.get("modified") or "",
                "aliases": json.dumps(vuln.get("aliases") or []),
                "references": json.dumps(vuln.get("references") or []),
                "source_url": f"https://osv.dev/vulnerability/{vuln_id}",
            },
        )

        # Relationship
        fixed_versions = []
        for affected in vuln.get("affected") or []:
            for r in affected.get("ranges") or []:
                for event in r.get("events") or []:
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        graph.query(
            """
            MATCH (p:Package {key: $key})
            MATCH (v:Vulnerability {id: $id})
            MERGE (p)-[r:HAS_VULNERABILITY]->(v)
            SET r.checked_version = $version,
                r.fixed_versions_json = $fixed,
                r.source = 'OSV.dev',
                r.version_status = 'AFFECTED'
            """,
            {
                "key": package_key,
                "id": vuln_id,
                "version": version,
                "fixed": json.dumps(sorted(set(fixed_versions))),
            },
        )
        loaded += 1

    print(f"Upserted {loaded} package-vulnerability relationships.")


def main():
    req_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("requirements.txt")
    if not req_file.exists():
        print(f"File not found: {req_file}")
        print("Usage: python ingest_from_requirements.py [requirements.txt]")
        sys.exit(1)

    print(f"Reading {req_file} ...")
    packages = parse_requirements(req_file)
    if not packages:
        print("No packages with versions found.")
        sys.exit(1)

    print(f"Found {len(packages)} packages:")
    for p in packages:
        print(f"  - {p['name']}=={p['version']}")

    print("\nQuerying OSV ...")
    batch = query_osv_batch(packages)

    records = []
    for item in batch:
        pkg = item["package"]
        vulns = item["vulns"]
        print(f"  {pkg['name']}=={pkg['version']} → {len(vulns)} vulnerabilities")
        for v in vulns:
            details = fetch_vuln_details(v["id"])
            if details:
                records.append({"package": pkg, "vulnerability": details})

    # Save raw for debugging
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RAW_DIR / "osv_from_requirements.json"
    out_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"\nSaved raw data → {out_file}")

    print("Loading into FalkorDB ...")
    upsert_to_graph(records)
    print("Done.")


if __name__ == "__main__":
    main()