# Index

Catalog of every page in this vault, organized by category. Updated whenever a new page is added.

---

## Schema & navigation

- [[CLAUDE]] — Vault schema, the fresh-instance entry point
- [[README]] — Human entry point
- [[log]] — Append-only chronological record

## Architecture

- [[architecture/current-state]] — As-is system overview
- [[architecture/target-state]] — Where we're going (across all sub-projects)

### Components

- [[architecture/components/splunk]] — SIEM
- [[architecture/components/sysmon]] — Sysmon: install metadata, EventCode + field reference, gotchas
- [[architecture/components/n8n]] — Workflow engine
- [[architecture/components/dfir-iris]] — Case management
- [[architecture/components/claude-api]] — AI triage in n8n
- [[architecture/components/splunk-mcp]] — Splunk MCP server (Desktop + Code)

## Sub-projects

- [[subprojects/2026-04-27-structured-outputs/README]] — A1: Structured Outputs (complete)
- [[subprojects/2026-04-28-iris-escalation-gate/README]] — A2: Iris Escalation Gate (complete)
- [[subprojects/2026-04-30-detection-foundations/README]] — D1: Detection Foundations (complete)
- [[subprojects/2026-05-12-enrichment-expansion/README]] — A3: Enrichment expansion (stub, awaiting brainstorm)
- [[subprojects/2026-07-13-splunk-investigation-agent/README]] - Phase 4: Splunk Investigation Agent (complete; grounded entity-scoped triage, live-run + deploy-bug fix)

## Detections

- [[detections/README]] — Detection catalog index (per-MITRE-technique pages)
- [[detections/_template]] — Skeleton for a new technique page
- [[detections/t1059-001-powershell-encoded]] — T1059.001 PowerShell encoded command (D1 worked example)

## Decisions (ADRs)

- [[decisions/0001-vault-structure]] — Vault layout: `vault/` subdirectory inside project root
- [[decisions/0002-claude-api-vs-subscription]] — When to use API vs Max subscription
- [[decisions/0003-split-structured-outputs-from-response-actions]] — Why we split Sub-project A
- [[decisions/0004-mirror-mcp-to-claude-code]] — Why Splunk MCP is configured in both Desktop and Code
- [[decisions/0005-additive-ioc-type-schema-enhancement]] — A2's additive `ioc_type` schema enhancement
- [[decisions/0006-splunk-add-on-for-microsoft-sysmon]] — D1's choice to install the Sysmon add-on + use `XmlWinEventLog:` source prefix
- [[decisions/0007-remove-slack-iris-native-gate]] — Remove Slack from workflow; move human-approval gate to IRIS-native review

## Runbooks

- [[runbooks/starting-the-vms]] — Boot sequence for the lab
- [[runbooks/n8n-workflow-deployment]] — Deploying / updating n8n workflows
- [[runbooks/secrets-management]] — Where secrets live and how to rotate them
- [[runbooks/splunk-mcp-setup]] — Installing Splunk MCP for Desktop and Code

## Workflows

- [[workflows/soc-triage-pipeline]] — The current production workflow

## Sources

- [[sources/session-notes/2026-04-27-mcp-mirror-fork]] — Fork session that mirrored MCP to VS Code
