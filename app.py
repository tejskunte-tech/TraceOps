#!/usr/bin/env python3
"""
TraceOps – Streamlit UI
Clean web interface for the security investigation agent.
Completely separate from the core agent/MCP code.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

# Load .env
load_dotenv(Path(__file__).resolve().parent / ".env")

st.set_page_config(
    page_title="TraceOps",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_ingestion(req_path: str) -> str:
    """Run the existing ingestion script and capture output."""
    result = subprocess.run(
        [sys.executable, "ingest_from_requirements.py", req_path],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent,
    )
    return result.stdout + result.stderr


def run_agent_sync(query: str) -> str:
    """
    Run the agent in a completely fresh process each time.
    This avoids asyncio TaskGroup / MCP session cleanup issues on repeated calls.
    """
    env = os.environ.copy()
    result = subprocess.run(
        [sys.executable, "traceops_agent.py", query],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent,
        env=env,
        timeout=180,
    )
    output = result.stdout
    if result.returncode != 0 and result.stderr:
        output += "\n\n[stderr]\n" + result.stderr
    return output


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ TraceOps")
    st.caption("Graph-Powered Security Investigation")
    st.markdown("---")

    st.subheader("1. Load Project")
    uploaded = st.file_uploader(
        "Upload requirements.txt",
        type=["txt"],
        help="Upload a requirements.txt file to analyze",
    )

    if uploaded is not None:
        if st.button("Ingest into FalkorDB", type="primary", use_container_width=True):
            with st.status("Ingesting data...", expanded=True) as status:
                st.write("Saving uploaded file...")
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False, encoding="utf-8"
                ) as tmp:
                    tmp.write(uploaded.getvalue().decode("utf-8"))
                    tmp_path = tmp.name

                st.write("Querying OSV for vulnerabilities...")
                st.write("Loading results into FalkorDB...")
                output = run_ingestion(tmp_path)
                st.code(output, language="text")
                status.update(label="Ingestion complete", state="complete")

    st.markdown("---")
    st.subheader("Quick Questions")
    quick = [
        "Rank packages by risk using the graph algorithm",
        "What should I fix first?",
        "Show multi-hop evidence for pillow",
        "Recommend remediation for django",
        "List all unknown or conflicting findings",
    ]
    for q in quick:
        if st.button(q, use_container_width=True):
            st.session_state["query"] = q

# ---------------------------------------------------------------------------
# Main area
# ---------------------------------------------------------------------------

st.title("TraceOps Investigation")
st.markdown("Ask the agent to investigate security risks using the graph.")

query = st.text_area(
    "Investigation request",
    value=st.session_state.get("query", ""),
    height=100,
    placeholder="e.g. Investigate the security risks and tell me what to fix first with clear reasoning.",
)

run_clicked = st.button("Investigate", type="primary")

if run_clicked and query.strip():
    with st.spinner("Agent is investigating (this may take 20–60 seconds)..."):
        try:
            result = run_agent_sync(query.strip())
            st.session_state["last_result"] = result
        except subprocess.TimeoutExpired:
            st.error("Investigation timed out. Please try a simpler question.")
            st.session_state["last_result"] = None
        except Exception as e:
            st.error(f"Error: {e}")
            st.session_state["last_result"] = None

if "last_result" in st.session_state and st.session_state["last_result"]:
    st.markdown("### Investigation Report")
    report = st.session_state["last_result"]
    # Clean decorative CLI lines
    lines = report.splitlines()
    cleaned = []
    for line in lines:
        if line.startswith("=====") or line.startswith("Model :") or line.startswith("Time  :"):
            continue
        if line.startswith("Investigating..."):
            continue
        if line.strip() == "------------------------------------------------------------":
            continue
        cleaned.append(line)
    st.markdown("\n".join(cleaned).strip())

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.markdown("---")
st.caption("TraceOps · FalkorDB Graph Hacks · Track 01: Agents That Act on Connected Data")