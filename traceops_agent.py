#!/usr/bin/env python3
"""
TraceOps Agent
LLM-powered security investigation agent that uses the TraceOps MCP server.
Uses Gemini 2.5 Flash-Lite with reliable manual tool calling.
"""
import sys
import io

# Force UTF-8 output so Unicode characters (→ etc.) don't crash on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Load .env from project root
load_dotenv(Path(__file__).resolve().parent / ".env")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MODEL = "gemini-3.1-flash-lite"
# MCP_SERVER_COMMAND = "python"
# MCP_SERVER_ARGS = ["traceops_mcp_server.py"]
MCP_SERVER_COMMAND = sys.executable
MCP_SERVER_ARGS = [str(Path(__file__).resolve().parent / "traceops_mcp_server.py")]
MAX_TOOL_ROUNDS = 15

# SYSTEM_PROMPT = """You are TraceOps, a graph-powered security investigation agent.

# Your job is to investigate software package vulnerabilities using the available tools.
# You must:

# 1. Use the graph tools to gather evidence (never invent findings).
# 2. Prefer multi-hop reasoning when useful (call multi_hop_investigation).
# 3. Clearly separate confirmed AFFECTED findings from UNKNOWN / conflicting ones.
# 4. Prioritize findings using get_package_risk_summary.
# 5. Always explain which tool results and graph paths support your conclusions.
# 6. Recommend concrete remediation actions only when evidence supports them.
# 7. If data is uncertain, say so explicitly.

# Be concise, structured, and evidence-based.
# When you have enough evidence, give a clear final report. Do not call more tools than needed.
# """

# SYSTEM_PROMPT = """You are TraceOps, a graph-powered security investigation agent.

# Your job is to investigate software package vulnerabilities using the available tools.
# You must:

# 1. Use the graph tools to gather evidence (never invent findings).
# 2. Prefer multi-hop reasoning when useful (call multi_hop_investigation).
# 3. Clearly separate confirmed AFFECTED findings from UNKNOWN / conflicting ones.
# 4. Prioritize findings using get_package_risk_summary or rank_packages_by_risk.
# 5. Always explain which tool results support your conclusions.
# 6. Recommend concrete remediation actions only when evidence supports them.
# 7. If data is uncertain, say so explicitly.

# Important style rules for the final answer:
# - Focus on: which packages are risky, what confirmed vulnerabilities they have, and how to fix them.
# - Give concrete upgrade commands when possible (e.g. pip install package>=version).
# - Do NOT explain Degree Centrality, graph algorithms, or methodology unless the user specifically asks for it.
# - Keep the answer practical and action-oriented.

# Be concise, structured, and evidence-based.
# When you have enough evidence, give a clear final report. Do not call more tools than needed.
# """

SYSTEM_PROMPT = """You are TraceOps, a graph-powered security investigation agent.

Your goal is to investigate package vulnerabilities using the available tools and give a clear final report.

Recommended investigation flow:
1. Call rank_packages_by_risk()
2. Call multi_hop_investigation() on the top 2 or 3 packages
3. Call list_unknown_or_conflicting()
4. Call recommend_remediation() on the top packages

Important rules:
- After you have enough evidence, STOP calling tools and write the final report.
- In the final report you MUST include:
  - Ranking of packages
  - Multi-hop evidence (show the actual path results from the tool)
  - Remediation commands
  - Any UNKNOWN findings
  - In the Multi-Hop Evidence section you MUST paste the actual path data returned by the multi_hop_investigation tool (do not just summarize the count). Show at least 2-3 real paths per package in a readable format.
- Never invent findings. Only use tool results.
- Be structured and concise.
"""

def mcp_tool_to_gemini(tool) -> types.FunctionDeclaration:
    """Convert an MCP tool definition into a Gemini FunctionDeclaration."""
    schema = tool.input_schema or {"type": "object", "properties": {}}
    return types.FunctionDeclaration(
        name=tool.name,
        description=tool.description or "",
        parameters=schema,
    )


async def call_mcp_tool(session: ClientSession, name: str, arguments: dict) -> Any:
    """Call an MCP tool and return the result content."""
    result = await session.call_tool(name, arguments=arguments)
    # MCP returns a list of content blocks; we join text parts
    parts = []
    for block in result.content:
        if hasattr(block, "text"):
            parts.append(block.text)
        else:
            parts.append(str(block))
    text = "\n".join(parts)
    try:
        return json.loads(text)
    except Exception:
        return text


async def run_investigation(user_query: str) -> str:
    """Run a full investigation using Gemini + TraceOps MCP tools."""

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return (
            "ERROR: Gemini API key not found.\n"
            "Create a .env file in the Traceops folder with:\n"
            "  GEMINI_API_KEY=your-key-here"
        )

    client = genai.Client(api_key=api_key)

    server_params = StdioServerParameters(
        command=MCP_SERVER_COMMAND,
        args=MCP_SERVER_ARGS,
        env=None,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Discover MCP tools
            mcp_tools = await session.list_tools()
            gemini_tools = [
                types.Tool(function_declarations=[mcp_tool_to_gemini(t)])
                for t in mcp_tools.tools
            ]

            # 2. Conversation state
            contents = [
                types.Content(
                    role="user",
                    parts=[types.Part(text=user_query)],
                )
            ]

            # 3. Tool-calling loop
            for round_num in range(MAX_TOOL_ROUNDS):
                response = await client.aio.models.generate_content(
                    model=MODEL,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        temperature=0.2,
                        tools=gemini_tools,
                    ),
                )

                # Collect function calls (if any)
                function_calls = []
                text_parts = []
                candidate = response.candidates[0]
                for part in candidate.content.parts:
                    if part.function_call:
                        function_calls.append(part.function_call)
                    elif part.text:
                        text_parts.append(part.text)

                # If no tool calls → final answer
                if not function_calls:
                    return "\n".join(text_parts) if text_parts else "(No response)"

                # Append model turn
                contents.append(candidate.content)

                # Execute tools and feed results back
                function_response_parts = []
                for fc in function_calls:
                    print(f"  -> calling tool: {fc.name}({dict(fc.args)})")
                    try:
                        result = await call_mcp_tool(session, fc.name, dict(fc.args))
                        result_str = json.dumps(result, indent=2, default=str)
                    except Exception as e:
                        result_str = json.dumps({"error": str(e)})

                    function_response_parts.append(
                        types.Part(
                            function_response=types.FunctionResponse(
                                name=fc.name,
                                response={"result": result_str},
                            )
                        )
                    )

                contents.append(
                    types.Content(role="user", parts=function_response_parts)
                )

            return "Reached maximum tool rounds. Please try a more focused question."


def main():
    print("=" * 60)
    print("  TraceOps — Graph-Powered Security Investigation Agent")
    print("=" * 60)
    print(f"Model : {MODEL}")
    print(f"Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
    else:
        print("Enter your investigation request (or press Enter for demo):")
        query = input("> ").strip()
        if not query:
            query = (
                "Investigate the security risks in my Python project. "
                "Focus on the most critical packages, show multi-hop evidence, "
                "and tell me what I should fix first with clear reasoning."
            )
            print(f"\nUsing demo query:\n{query}\n")

    print("-" * 60)
    print("Investigating...\n")

    try:
        result = asyncio.run(run_investigation(query))
        print(result.replace("→", "->").replace("←", "<-"))
    except Exception as e:
        print(f"Agent error: {e}")
        import traceback
        traceback.print_exc()
        print("\nMake sure:")
        print("  1. FalkorDB is running on localhost:6379")
        print("  2. GEMINI_API_KEY is set in .env")
        print("  3. You are in the Traceops folder")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()