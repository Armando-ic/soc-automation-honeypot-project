# SOC Automation Project

An AI-augmented SOC (Security Operations Center) automation lab. Splunk SIEM ingests endpoint telemetry, fires saved-search alerts into an n8n SOAR pipeline, where Claude Opus 4.7 performs Tier-1 triage with VirusTotal/AbuseIPDB enrichment tools, then writes the result into DFIR-Iris as a case-management alert.

Built as a portfolio project to demonstrate detection engineering, SIEM operations, and human-in-the-loop AI for security workflows.

## Architecture

```
Windows endpoint                            Splunk SIEM            n8n SOAR              DFIR-Iris
(Sysmon + Universal     ─►   ingestion ─►  saved-search    ─►   Claude triage    ─►    case alert
 Forwarder + Atomic                          alert action          + enrichment           + analyst
 Red Team)                                   (webhook)             tools                  review
```

Lab on a private VMware NAT subnet: Win10-v2 (192.168.129.130), Splunk (.131), n8n (.132), IRIS (.133). Full topology and host inventory in [vault/architecture/current-state.md](vault/architecture/current-state.md).

## What's in the repo

| Path | Contents |
|---|---|
| [vault/](vault/) | Documentation vault — architecture, decisions (ADRs), sub-projects, runbooks, detection catalog |
| [JSON/](JSON/) | n8n workflow exports + Iris OpenAPI spec |
| [scripts/](scripts/) | Python automation scripts (Sysmon install, ART invocation, paramiko SSH helpers) |

## What's shipped

Three sub-projects shipped end-to-end:

- **A1 — Structured Outputs** ([spec](vault/subprojects/2026-04-27-structured-outputs/spec.md)) — replaced freeform Claude output with a `submit_triage_result` tool returning a versioned structured schema, enabling programmatic IOC routing and severity mapping into Iris.
- **A2 — Iris Escalation Gate** ([spec](vault/subprojects/2026-04-28-iris-escalation-gate/spec.md)) — Slack-interactive human-approval gate via signed Wait-resume URLs and Iris's escalate endpoint. **Retired by ADR 0007** (Slack removed; approval moves to IRIS-native review); design preserved in vault as historical reference.
- **D1 — Detection Foundations** ([spec](vault/subprojects/2026-04-30-detection-foundations/spec.md)) — Sysmon 15.20 + SwiftOnSecurity config on the endpoint, Atomic Red Team for purple-team test execution, one worked-example detection (T1059.001 PowerShell Encoded Command) firing end-to-end through the pipeline.

D1 frozen at 2026-05-12 after a from-scratch rebuild of n8n + IRIS (forced by an unrelated OneDrive incident — recovery story documented in [vault/log.md](vault/log.md) entry 2026-05-08). Full chain re-validated post-rebuild: IRIS alert #4 produced from a real ART-shape event traversing Win10 → Sysmon → UF → Splunk saved search → webhook → n8n → Claude → IRIS.

## Highlights worth reading

- **[vault/detections/t1059-001-powershell-encoded.md](vault/detections/t1059-001-powershell-encoded.md)** — D1's worked-example detection page. Captures the SPL, what events look like in Sysmon's wire format, the live-fire evidence trail (alerts #51, #52 on 2026-04-30 → #4 on 2026-05-12 post-rebuild), and the gotchas surfaced along the way.
- **[vault/decisions/](vault/decisions/)** — 7 ADRs documenting non-obvious choices: vault layout, API vs subscription tradeoffs, MCP mirroring, sub-project splitting, the additive `ioc_type` schema enhancement, the Sysmon add-on decision, and the Slack-removal / IRIS-native-gate pivot.
- **[vault/architecture/components/](vault/architecture/components/)** — One reference doc per major component (Splunk, Sysmon, n8n, dfir-iris, claude-api, splunk-mcp). Captures install metadata, EventCode/field references, ID catalogs, and gotchas in operational terms.
- **[vault/subprojects/2026-04-30-detection-foundations/notes.md](vault/subprojects/2026-04-30-detection-foundations/notes.md)** — D1's working notes. Includes the Phase 11 (2026-05-12) post-rebuild revalidation gotchas, including a non-obvious Splunk REST-API trap that took a 4-hour debug to surface.

## Tech stack

| Layer | Stack |
|---|---|
| SIEM | Splunk Enterprise 10.2.2 + Splunk_TA_microsoft_sysmon |
| Endpoint telemetry | Sysmon 15.20 + SwiftOnSecurity config (commit `1836897f`) + Splunk Universal Forwarder |
| Purple-team execution | Atomic Red Team (Red Canary) + AtomicTestHarnesses |
| SOAR | n8n on Ubuntu Server 24.04 via docker-compose |
| AI triage | Claude Opus 4.7 via Anthropic API, agentic with tool-use (AbuseIPDB, VirusTotal, structured-output submission) |
| Case management | DFIR-Iris v2.4.22 on Ubuntu Server 24.04 via docker-compose |
| Lab infrastructure | VMware Workstation Pro on Windows 11 host, NVMe-resident VMs |

## Next steps

- **A3 — Enrichment Expansion** ([stub](vault/subprojects/2026-05-12-enrichment-expansion/README.md)) — add 2–3 new IOC enrichment sources (urlscan.io, URLhaus, IP2Location) beyond the current AbuseIPDB + VirusTotal pair. Awaiting brainstorm.
- **Pivot toward Microsoft Sentinel / Azure SOC tooling.** D1 was frozen to clear the runway for this. The Splunk fundamentals (SPL, detection engineering, MITRE mapping, SOAR integration) translate; KQL and Azure-native security tooling are the next learning surface. Tracked separately from this repo.

## Reading order for a fresh visitor

1. This README (you are here)
2. [vault/architecture/current-state.md](vault/architecture/current-state.md) — what the lab looks like today
3. [vault/detections/t1059-001-powershell-encoded.md](vault/detections/t1059-001-powershell-encoded.md) — the worked example as a microcosm of how the whole project operates
4. Any sub-project's spec → plan → runbook → notes — for end-to-end design + execution + ops + learnings on a specific piece of work

## What's deliberately NOT in this repo

- **Secrets** — API keys, VM passwords, IRIS admin password, etc. Runtime values live in `.env` (gitignored, see `.env.example`); a human-readable lab credential sheet at `SOC-Automation-Project.md` (gitignored) is consulted by the install runbooks. See [vault/runbooks/secrets-management.md](vault/runbooks/secrets-management.md) for the full layout and the 2026-05-18 pre-publish remediation notes.
- **VM disk images** — too large for git. The vault documents how to rebuild each VM from scratch in [vault/subprojects/2026-04-30-detection-foundations/runbook.md](vault/subprojects/2026-04-30-detection-foundations/runbook.md).
- **Splunk MCP server source** — kept locally under `splunk-mcp-main/` for development convenience but not redistributed here. Upstream: [livehybrid/splunk-mcp](https://github.com/livehybrid/splunk-mcp). Project notes on the local mirror are in [vault/sources/session-notes/2026-04-27-mcp-mirror-fork.md](vault/sources/session-notes/2026-04-27-mcp-mirror-fork.md).
- **OneDrive-trapped legacy VMs** — see the 2026-05-08 log entry.

## License + attribution

Personal portfolio project. Original tutorial inspiration: MyDFIR (Stephen) — *SOC Automation Project 2.0* video series and bonus modules. This repo extends that tutorial into structured outputs, an escalation gate, detection foundations with Sysmon + ART, and a fresh-from-scratch rebuild story.
