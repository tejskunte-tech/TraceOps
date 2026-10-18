# TraceOps — Project Roadmap and Implementation Guide

**Project:** TraceOps — Graph-Powered Security Investigation Agent
**Primary technology:** Python, FalkorDB, OSV vulnerability data, MCP, LLM-based agent
**Current phase:** Graph construction and version validation completed; MCP and agent implementation next.

---

# 1. Project Vision

## What are we building?

TraceOps is an agent that uses a graph database to investigate software security risks, select investigation tools, reason across connected information, recommend actions, and explain its conclusions.

The goal is not simply to build a vulnerability scanner or a dashboard.

The goal is to build an **agent that uses connected data to decide what to investigate and what to do next**.

For example, a user could ask:

> Investigate the security risks in my Python project, determine which vulnerabilities should be addressed first, explain the evidence, and recommend the safest remediation steps.

TraceOps should be able to:

1. Understand the user's investigation request.
2. Identify relevant packages and vulnerabilities.
3. Query FalkorDB for connected evidence.
4. Follow relationships across multiple graph hops.
5. Select additional tools based on the information it discovers.
6. Investigate vulnerability severity, affected versions, dependencies, and fixes.
7. Distinguish confirmed findings from uncertain or conflicting evidence.
8. Recommend prioritized remediation actions.
9. Explain which evidence supports each conclusion.
10. Record investigation results and verify completed actions.

## Core requirements

The finished project must demonstrate all five of these capabilities:

* **Multi-hop reasoning:** Investigate relationships across several connected graph entities.
* **Graph tools and algorithms:** Use graph queries and, where appropriate, graph algorithms as tools available to the agent.
* **MCP tool selection:** Expose tools through MCP and allow the agent to select and call them.
* **Actions based on graph evidence:** Recommend or execute controlled actions based on investigation results.
* **Explainable results:** Show the evidence, graph paths, tool calls, decisions, uncertainty, and recommended actions.

---

# 2. What We Have Completed So Far

The following items are supported by the command outputs collected during development.

## 2.1 Project environment

The project is located at:

`C:\Users\stkga\Downloads\PROJECTS\Traceops`

A Python virtual environment is active:

`(.venv)`

The project uses Python scripts for data processing, vulnerability validation, graph synchronization, and verification.

## 2.2 Vulnerability data ingestion

The project has detailed OSV vulnerability records in:

`data/raw/osv_detailed.json`

The records include package information, vulnerability identifiers, affected-version ranges, advisory details, and references.

Five Python packages are represented:

* requests
* django
* flask
* urllib3
* pillow

The dataset contains 107 package-vulnerability records.

## 2.3 FalkorDB graph

A FalkorDB graph named `traceops` has been created and populated.

The existing graph includes package nodes and vulnerability nodes connected through:

`(:Package)-[:HAS_VULNERABILITY]->(:Vulnerability)`

The relationships include properties such as:

* `checked_version`
* `fixed_versions_json`
* `source`

The graph has also been extended with validation information, including:

* `version_status`
* `validation_reason`

The exact property names should be confirmed against the current database schema before adding new graph tools.

## 2.4 Version validation

The following script exists:

`validate_affected_versions.py`

It reads the detailed OSV records and writes its results to:

`data/validated_vulnerabilities.json`

The validator uses Python's `packaging.version.Version` to compare Python package versions with supported ecosystem version ranges.

It recognizes three outcomes:

* `AFFECTED`
* `NOT_AFFECTED`
* `UNKNOWN`

The validator also records reasons for its conclusions and identifies range types that it cannot evaluate.

The current version of the validator has successfully processed 107 records. The latest reported results were:

| Status       | Records |
| ------------ | ------: |
| AFFECTED     |     106 |
| NOT_AFFECTED |       0 |
| UNKNOWN      |       1 |

These are the last confirmed results from the recorded execution, not a guarantee that the dataset or results remain unchanged.

## 2.5 Validation audit

The following script exists:

`audit_validation.py`

It summarizes validation outcomes by package and audits the available range types.

The dataset contains both:

* `ECOSYSTEM` ranges, which can generally be compared with package versions.
* `GIT` ranges, which use repository commit identifiers and cannot be directly compared with package version strings.

The audit previously reported 146 ecosystem ranges and 8 Git ranges.

## 2.6 Graph synchronization

The following scripts exist:

* `sync_validation_to_graph.py`
* `verify_validation_in_graph.py`
* `audit_graph_status.py`

A synchronization run reported:

* Input records: 107
* Relationships updated: 107
* Records without matching relationships: 0
* Failed updates: 0

The graph audit subsequently reported 107 relationships inspected, with 106 marked `AFFECTED` and one marked `UNKNOWN`.

This establishes that the validation results were synchronized into the graph. It does not, by itself, prove that every advisory classification is correct.

## 2.7 Known unresolved data-quality issue

The advisory `PYSEC-2022-42980` for Pillow contains conflicting information.

The checked version is `9.0.0`.

Its ecosystem range states:

* Introduced: `9.2.0`
* Fixed: `9.3.0`

Therefore, the ecosystem range excludes Pillow `9.0.0`.

However, the advisory's explicit `versions` list also contains `9.0.0`.

The record additionally contains a Git range whose commit hash cannot be compared directly with `9.0.0`.

This inconsistency should be retained as an explicit data-quality issue. Do not silently assume the package is safe or vulnerable until the evidence has been reconciled.

**Important:** This is one unresolved data-quality issue. It must not prevent development of the MCP server or the agent.

---

# 3. What We Have Not Built Yet

The graph and validation pipeline form the foundation, but they are not yet the complete agent.

The following capabilities still need implementation and testing.

| Capability                        | Current state                                         |
| --------------------------------- | ----------------------------------------------------- |
| Vulnerability ingestion           | Implemented                                           |
| Package and vulnerability graph   | Implemented                                           |
| Version validation                | Implemented, with one unresolved conflicting advisory |
| Validation synchronization        | Implemented                                           |
| Graph status verification         | Implemented                                           |
| MCP server                        | Not yet confirmed running                             |
| LLM-based agent runtime           | Not yet implemented or verified                       |
| Dynamic tool selection            | Not yet implemented or verified                       |
| Multi-hop graph investigation     | Not yet implemented or verified                       |
| Graph algorithm tools             | Not yet implemented or verified                       |
| Risk prioritization               | Needs implementation                                  |
| Remediation planning              | Needs implementation                                  |
| Explainable investigation reports | Needs implementation                                  |
| Action approval and audit trail   | Needs implementation                                  |
| End-to-end evaluation             | Needs implementation                                  |

Do not rebuild the existing components merely because these later capabilities are missing.

---

# 4. Target Architecture

The intended architecture is:

```text
                     USER
                       |
                       v
             TraceOps Agent Runtime
                       |
             Understand the request
                       |
             Plan the investigation
                       |
                       v
              MCP Tool Interface
                       |
          +------------+-------------+
          |            |             |
          v            v             v
      Graph Tools  Security Tools  Analysis Tools
          |            |             |
          +------------+-------------+
                       |
                       v
                  FalkorDB
                       |
            Packages and Vulnerabilities
            Validation and Relationships
            Dependency and Remediation Data
                       |
                       v
               Investigation Evidence
                       |
                       v
              Agent Reasoning Loop
                       |
          +------------+-------------+
          |            |             |
          v            v             v
      More Queries  Risk Ranking  Action Planning
          |            |             |
          +------------+-------------+
                       |
                       v
             Explainable Final Report
                       |
                       v
           Approval / Controlled Actions
                       |
                       v
                Verification and Audit
```

The agent should not access the database through arbitrary model-generated database commands.

Instead, it should use a controlled collection of tools. Each tool should have a clear purpose, a documented input schema, bounded output, and defined permissions.

---

# 5. Implementation Roadmap

Follow the stages in order. Finish and test one stage before moving to the next.

## Stage 1 — Stabilize the existing foundation

**Objective:** Establish a reliable baseline before building the agent.

### Tasks

1. Back up `data/validated_vulnerabilities.json`.
2. Run `validate_affected_versions.py`.
3. Run `audit_validation.py`.
4. Confirm that the graph contains the expected packages and vulnerability relationships.
5. Confirm that the graph's validation properties match the JSON results.
6. Record the Pillow advisory as a known unresolved issue.
7. Avoid further validator changes unless a specific test identifies a real defect.

### Acceptance criteria

* The validator completes successfully.
* The expected records are present.
* Every validation outcome has an explanation.
* The graph and JSON output agree.
* The unresolved advisory remains visible.

This stage is a baseline check, not a reason to restart the pipeline.

## Stage 2 — Build the MCP server

**Objective:** Make graph investigation capabilities available as discoverable tools.

Create:

`traceops_mcp_server.py`

Use the Python MCP SDK and the existing FalkorDB connection.

Install the SDK in the existing virtual environment:

```powershell
pip install "mcp>=1.28,<2"
```

Use the SDK documentation to confirm the installed API:

https://py.sdk.modelcontextprotocol.io/v1/

### First MCP tools

Implement the following tools.

#### Tool 1: `list_packages`

Purpose:

List packages stored in the graph.

Expected information:

* Package name
* Ecosystem
* Available package metadata

#### Tool 2: `list_vulnerabilities_for_package`

Input:

`package_name`

Purpose:

Return vulnerability findings connected to the specified package.

Expected information:

* Package properties
* Vulnerability properties
* Relationship properties
* Validation status and reason, if stored

#### Tool 3: `investigate_advisory`

Input:

`advisory_id`

Purpose:

Retrieve the graph evidence associated with a specific advisory.

Expected information:

* Advisory identifier
* Package
* Checked version
* Validation status
* Severity, when available
* Fixed versions, when available
* Source references, when available

#### Tool 4: `get_package_risk_summary`

Input:

`package_name`

Purpose:

Summarize findings for a package.

It should count confirmed affected findings, unaffected findings, and unknown findings separately.

Do not treat the number of findings as a complete measure of risk.

#### Tool 5: `trace_dependency_path`

Inputs:

* Source package
* Target package, or a suitable path-search parameter

Purpose:

Find a dependency path through the graph.

This tool requires dependency relationships to exist. The current graph is known to contain package-to-vulnerability relationships, but dependency edges have not yet been confirmed.

If dependencies are missing, implement dependency ingestion before claiming this capability works.

### MCP design requirements

* Use parameterized graph queries.
* Validate tool inputs.
* Set result limits.
* Return structured, JSON-compatible data.
* Avoid exposing credentials or sensitive configuration.
* Handle missing nodes and query errors.
* Keep read-only tools separate from write-capable tools.

### Test the server

Run:

```powershell
python .\traceops_mcp_server.py
```

Confirm that the server starts without errors.

Then connect an MCP client or use an appropriate MCP inspector to verify tool discovery and invocation.

A server starting successfully is not enough. Each tool must return the correct information from FalkorDB.

### Acceptance criteria

* The MCP server starts.
* Tools are discoverable by an MCP client.
* A package query returns the expected records.
* An advisory query returns the expected evidence.
* Unknown package names and advisory IDs are handled safely.
* All read-only tools are verified.

**Deliverable:** A tested `traceops_mcp_server.py`.

## Stage 3 — Build the agent runtime

**Objective:** Let an LLM choose which tools to call based on the investigation.

Create:

`traceops_agent.py`

The agent runtime should:

1. Accept a user investigation request.
2. Determine what information is needed.
3. Discover available MCP tools.
4. Choose a tool.
5. Execute the tool through an MCP client.
6. Inspect the result.
7. Decide whether more evidence is needed.
8. Select additional tools when appropriate.
9. Produce a final report grounded in retrieved evidence.

### Important distinction

A script that always calls the same three tools in the same order is a workflow, not convincing evidence of dynamic agent tool selection.

For this project, the LLM must be able to select tools based on the question and results.

Use an LLM provider and model that support tool calling, or implement the MCP-compatible tool loop through an appropriate agent framework.

Keep provider credentials in environment variables. Never hardcode API keys.

### Agent execution limits

Implement:

* Maximum tool calls per investigation
* Maximum execution time
* Tool input validation
* Output-size limits
* Error handling
* Cancellation support, where practical
* A record of tool names, inputs, and results

Treat graph content, advisory text, and retrieved external data as untrusted evidence. Do not follow instructions embedded in retrieved data.

### Acceptance criteria

The agent can answer at least these questions:

1. Which vulnerabilities are connected to Requests?
2. What evidence exists for a specific advisory?
3. Which finding needs more investigation?
4. What additional tool should be called based on the first tool's result?

**Deliverable:** A working agent runtime that selects MCP tools dynamically.

## Stage 4 — Implement multi-hop investigation

**Objective:** Demonstrate reasoning across connected graph entities, not just single-node lookups.

A multi-hop investigation follows multiple relationships to assemble relevant evidence.

For example:

```text
Package
   |
   | HAS_VULNERABILITY
   v
Vulnerability
   |
   | AFFECTS / ASSOCIATED_WITH
   v
Affected Component or Service
   |
   | DEPENDS_ON
   v
Dependent Package or Application
```

The exact relationships must match the actual graph schema. The diagram describes a target model, not relationships already confirmed in the current database.

### First investigate the existing schema

Inspect:

* All node labels
* All relationship types
* Important node properties
* Important relationship properties
* Whether dependency edges exist
* Whether application or project nodes exist
* Whether fixed-version and severity data are stored

Do not assume relationships exist because they appear in the target architecture.

### Extend the graph if necessary

If the graph only connects packages to vulnerabilities, ingest the additional data needed for genuine multi-hop reasoning.

Potential additions include:

* Project-to-package relationships
* Package-to-dependency relationships
* Vulnerability-to-CVE or advisory relationships
* Vulnerability-to-remediation relationships
* Package-version or release information

Only add entities that support a defined investigation use case.

### Multi-hop tools

Create tools such as:

* `find_vulnerability_paths`
* `find_affected_dependents`
* `trace_dependency_path`
* `find_related_advisories`
* `compare_remediation_options`

Each tool should return the actual path and the evidence supporting it.

### Graph algorithms

Once the relevant graph structure exists, consider algorithms such as:

* Shortest path for tracing connections
* Reachability for identifying potentially affected dependents
* Centrality for understanding structurally important nodes
* Community detection if grouping related components is useful

Do not use algorithms simply to claim that the project uses graph analytics. Every algorithm must answer a defined security question.

### Acceptance criteria

Demonstrate at least one investigation that:

1. Starts with a package.
2. Finds its connected vulnerabilities.
3. Traverses an additional relationship.
4. Identifies another relevant entity.
5. Uses the result to change or refine the investigation.
6. Returns the full path and supporting evidence.

**Deliverable:** A working multi-hop graph investigation.

## Stage 5 — Build evidence-based risk prioritization

**Objective:** Decide which findings deserve attention first.

Create a risk-analysis module, for example:

`traceops/risk.py`

Do not rely on the number of advisories alone.

Consider available evidence such as:

* Advisory severity and CVSS score
* Confirmed affected-version status
* Whether the vulnerable package is actually installed in the target project
* Dependency reachability
* Exploitability information, if available
* Fix availability
* Uncertainty or conflicting source data

### Example prioritization policy

1. Review confirmed affected findings with critical severity first.
2. Consider exploitability and exposure when reliable evidence exists.
3. Consider high-severity affected dependencies and their impact on other components.
4. Identify findings with available fixes.
5. Keep uncertain or conflicting findings in a separate review category.

Do not invent CVSS scores or exploitability evidence when those fields are missing.

An `UNKNOWN` result must not silently be treated as `NOT_AFFECTED`.

### Acceptance criteria

* The agent explains why one finding ranks above another.
* Every ranking factor is tied to evidence.
* Missing data is explicitly identified.
* The output distinguishes urgency from confidence.

**Deliverable:** A risk-ranking tool with explainable results.

## Stage 6 — Build remediation planning

**Objective:** Turn findings into actionable recommendations.

Create:

`traceops/remediation.py`

The module should determine:

* Which package is affected
* Which installed version is involved
* Which advisory applies
* Whether a fixed version is documented
* Which upgrade candidates are supported by the available evidence
* Whether the upgrade could affect other dependencies
* What validation is required after the upgrade

### Important safety rule

Do not assume that the highest version listed in an advisory is always the right upgrade.

A remediation recommendation must consider the package's supported release line, compatibility constraints, and the project's dependency configuration.

If compatibility information is missing, recommend investigation rather than asserting that an upgrade is safe.

### Separate recommendation from execution

Initially, TraceOps should recommend changes without modifying the user's codebase.

Later, if write-capable actions are added:

1. Generate a proposed change.
2. Explain the expected effect.
3. Ask for explicit approval.
4. Apply the change.
5. Run tests and security checks.
6. Report the result.

The agent must not claim a change succeeded until it has verified the outcome.

### Acceptance criteria

* Every recommendation identifies the finding it addresses.
* The recommendation has a source or an explicit uncertainty note.
* Suggested changes can be reviewed before execution.
* Verification results are recorded.

**Deliverable:** A remediation planner with a safe approval process.

## Stage 7 — Make results explainable

**Objective:** Every important conclusion should be traceable to graph evidence.

Create:

`traceops/reporting.py`

The final report should include:

### Investigation summary

What was asked and what the agent investigated.

### Findings

For each finding:

* Package and installed version
* Advisory identifier
* Severity, when available
* Validation status
* Source reference

### Graph evidence

Show the relevant nodes, relationships, and paths.

### Agent tool activity

Record:

* Tool selected
* Why the tool was relevant
* Parameters supplied
* Result summary
* How the result affected the next step

### Decision explanation

Explain which facts support the recommendation, which assumptions were made, and what evidence is missing.

### Recommended actions

For each recommendation, include:

* Proposed action
* Expected benefit
* Relevant finding
* Confidence or uncertainty
* Verification method

### Audit record

Store a structured investigation record containing the request, tool-call history, evidence references, final status, and recommendations.

Keep secrets and unnecessary sensitive data out of logs.

**Deliverable:** An evidence-backed investigation report.

## Stage 8 — Build an action and verification layer

**Objective:** Allow the agent to take controlled actions based on the graph.

Initially, implement safe actions such as:

* Create a remediation plan
* Generate a report
* Mark a finding for review
* Record an investigation result
* Produce a proposed dependency update

If the graph is updated, validate the change and record its provenance.

Later, support controlled actions such as creating a pull request or applying an approved dependency update.

Use a separate set of write-capable tools with stricter permissions than the read-only investigation tools.

### Safety requirements

* Require approval for consequential changes.
* Do not execute arbitrary shell commands generated by the LLM.
* Restrict filesystem and repository access.
* Validate every action's parameters.
* Record the before-and-after state.
* Verify that the action achieved its intended result.
* Provide a way to reject or roll back changes where feasible.

**Deliverable:** A controlled action layer with verification and an audit trail.

---

# 6. End-to-End Demonstration

The final demonstration should use a real investigation request.

Example:

> Investigate Requests 2.28.0, identify the important vulnerabilities, find related evidence in the graph, prioritize the findings, and recommend a remediation plan.

The expected flow is:

1. The agent identifies the package.
2. It calls the relevant MCP graph tool.
3. It retrieves the package's vulnerability relationships.
4. It evaluates the validation status and source information.
5. It selects another tool to investigate important findings.
6. It follows additional graph relationships where the schema supports them.
7. It ranks findings based on documented evidence.
8. It identifies fixes and compatibility information when available.
9. It flags uncertain findings.
10. It generates an explainable remediation plan.
11. It asks for approval before any consequential write action.
12. It verifies approved changes and records the outcome.

The agent must not automatically upgrade dependencies just because an advisory exists.

---

# 7. Testing and Evaluation

Create a test suite that measures correctness rather than merely demonstrating that the scripts run.

Suggested test areas:

| Test                         | Expected result                                          |
| ---------------------------- | -------------------------------------------------------- |
| Known package lookup         | Returns the correct package findings                     |
| Known advisory lookup        | Returns the correct advisory evidence                    |
| Unknown package              | Returns a clear empty result                             |
| Unknown advisory             | Returns a clear empty result                             |
| Conflicting version evidence | Preserves the conflict and uncertainty                   |
| Tool-selection test          | Agent chooses relevant tools for different questions     |
| Multi-hop test               | Returns a valid path supported by existing relationships |
| Risk-ranking test            | Uses documented factors and evidence                     |
| Remediation test             | Does not invent fixed versions                           |
| MCP failure test             | Reports the failure instead of fabricating a result      |
| Approval test                | Refuses to perform an unapproved consequential action    |
| Audit test                   | Records the relevant tool calls and final decision       |

### Evaluation metrics

Track:

* Tool-call success rate
* Investigation completion rate
* Correctness against known test cases
* Validity of returned graph paths
* Unsupported-claim rate
* Correct handling of uncertain evidence
* Remediation recommendation correctness
* Action verification success rate

For the final evaluation, prepare a small set of known scenarios with expected evidence and outcomes.

---

# 8. Suggested Project Structure

Extend the existing project rather than replacing it.

```text
Traceops/
│
├── .venv/
│
├── data/
│   ├── raw/
│   │   └── osv_detailed.json
│   ├── validated_vulnerabilities.json
│   └── validated_vulnerabilities_backup.json
│
├── validate_affected_versions.py
├── audit_validation.py
├── sync_validation_to_graph.py
├── verify_validation_in_graph.py
├── audit_graph_status.py
├── inspect_graph.py
├── inspect_git_ranges.py
│
├── traceops_mcp_server.py
├── traceops_agent.py
│
├── traceops/
│   ├── __init__.py
│   ├── graph_tools.py
│   ├── risk.py
│   ├── remediation.py
│   ├── reporting.py
│   └── audit.py
│
├── tests/
│   ├── test_graph_tools.py
│   ├── test_agent.py
│   ├── test_risk.py
│   ├── test_remediation.py
│   └── test_reporting.py
│
├── .env.example
├── .gitignore
├── requirements.txt
└── TRACEOPS_ROADMAP.md
```

This is the target structure. Create files as each stage begins; do not create empty files for every module at once.

Keep actual credentials in a local `.env` file excluded from version control.

---

# 9. Working Rules to Avoid Going in Circles

Follow these rules throughout implementation.

1. Do not rewrite a working script without a specific defect or requirement.
2. Do not repeat validation work merely because a later feature is missing.
3. Do not change classifications just to maximize the number of `AFFECTED` results.
4. Do not assume graph nodes or relationships exist; inspect the schema.
5. Do not build a dashboard before the agent's core investigation works.
6. Do not claim multi-hop reasoning if the agent only performs a fixed sequence of lookups.
7. Do not claim MCP tool selection until a client has successfully discovered and invoked the tools.
8. Do not invent severity, fixed versions, graph paths, or remediation evidence.
9. Keep a record of unresolved data-quality issues without allowing one issue to block unrelated development.
10. Every stage must have a test and a clear completion criterion.
11. Make one focused change at a time.
12. Preserve the last working version before making substantial changes.

---

# 10. Immediate Action Plan

This is the current execution checklist.

## Phase A — Start with MCP

* [ ] Back up the validated JSON file.
* [ ] Confirm FalkorDB is running.
* [ ] Inspect the actual graph labels, relationship types, and properties.
* [ ] Install the MCP Python SDK in the existing virtual environment.
* [ ] Create `traceops_mcp_server.py`.
* [ ] Implement `list_packages`.
* [ ] Implement `list_vulnerabilities_for_package`.
* [ ] Implement `investigate_advisory`.
* [ ] Test the server using an MCP client or inspector.
* [ ] Confirm the returned data matches FalkorDB.

## Phase B — Add the agent

* [ ] Create `traceops_agent.py`.
* [ ] Configure an LLM provider with tool-calling support.
* [ ] Connect the agent to the MCP server.
* [ ] Implement dynamic tool selection.
* [ ] Implement the iterative tool-call loop.
* [ ] Add limits, error handling, and audit logging.
* [ ] Test multiple distinct investigation requests.

## Phase C — Demonstrate graph reasoning

* [ ] Inspect the current graph schema.
* [ ] Determine whether dependency edges exist.
* [ ] Ingest additional relationship data if required.
* [ ] Implement a multi-hop investigation tool.
* [ ] Add a graph algorithm only when it supports a defined security question.
* [ ] Verify that returned paths correspond to real graph relationships.

## Phase D — Turn reasoning into action

* [ ] Implement evidence-based risk ranking.
* [ ] Implement remediation planning.
* [ ] Generate explainable investigation reports.
* [ ] Add approval-controlled actions.
* [ ] Verify the result of each approved action.
* [ ] Add an audit trail.

## Phase E — Final demonstration

* [ ] Run an end-to-end investigation.
* [ ] Show the agent selecting tools dynamically.
* [ ] Show a valid multi-hop graph path.
* [ ] Show evidence-based risk prioritization.
* [ ] Show a remediation recommendation.
* [ ] Show uncertainty handling.
* [ ] Demonstrate an approval and verification flow.
* [ ] Document the evaluation results and limitations.

---

# 11. Definition of Done

TraceOps is ready for its intended demonstration when it can:

1. Accept a natural-language security investigation request.
2. Select and invoke MCP tools based on that request.
3. Query FalkorDB and reason over multiple connected entities.
4. Use graph queries and at least one justified graph-analysis capability.
5. Identify important security findings using evidence.
6. Recommend appropriate remediation steps.
7. Distinguish confirmed results from uncertainty.
8. Explain its decisions with graph paths, source data, and tool-call history.
9. Perform only approved consequential actions.
10. Verify and record the results of those actions.
11. Pass a repeatable test suite.

**The most important principle:** Build the agent around the existing graph. The graph is the evidence layer, MCP is the tool interface, the LLM is the investigation planner, and the action layer turns evidence-backed conclusions into controlled outcomes.

---

# 12. Next Step — Do This Now

Do not start with risk scoring, a dashboard, or another round of version-validation changes.

Start by inspecting the graph schema and implementing the MCP server.

The immediate objective is simple:

**Get one MCP tool to query FalkorDB successfully, then expose the remaining read-only investigation tools and verify them through an MCP client.**

Only after this works should you implement the LLM-driven agent runtime.
