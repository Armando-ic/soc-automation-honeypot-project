# Honeypot Agentic-SOC Upgrade — HANDOFF (2026-06-24)

**For the next fresh Claude instance. Read this first**, then the spec + Plan 0A.

## What this is
Phase 0 of the approved AI-upgrade roadmap: an internet-exposed **Windows honeypot → Splunk → n8n SOAR
(max enrichment APIs + Qdrant) → Claude Opus triage (verifier-gated) → DFIR-Iris**, with **CrowdStrike
Falcon** as detect-only EDR + `Contain` auto-response. Real attacker telemetry replaces the old synthetic
(Atomic Red Team) data. Purpose: build agentic-SOC vocabulary toward the Google/Mandiant "Associate
Security Analyst, Agentic Security Operations" role (a 2–3 yr anchor per the user's own playbook), and
keep applying to reachable seats (Expel/Panther/etc.) in parallel.

## Read-first docs
- Spec: `docs/superpowers/specs/2026-06-22-honeypot-agentic-soc-design.md` ← **PARENT workspace, not this repo**
- Plan 0A: `docs/superpowers/plans/2026-06-22-honeypot-phase0a-infrastructure.md` ← PARENT
- CrowdStrike API reference: `infra/honeypot/crowdstrike-api-notes.md` (this repo)
- Config-as-docs: `infra/honeypot/README.md`, `nsg-rules.md`, `RUNBOOK.md` (this repo)

## Branch & conventions
- Work on **`ai-upgrade`** (off `v2-azure`) in `SOC_Automation_Project`. **NOT pushed.**
- Strategy docs live in the PARENT `docs/superpowers/` (NOT a git repo — just files). The repo holds
  implementation artifacts under `infra/honeypot/`.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Never `git add -A`** — untracked `Personal/` and `.playwright-mcp/` must stay out. Add specific files.
- **User preference (memory):** present Azure portal forms as **field-by-field labeled lists**, not prose/wide tables.
- Decomposition: Plan 0A (infra) → 0B (Falcon) → 0C (pipeline software, TDD) → 0D (n8n wiring).

## ai-upgrade commits so far
```
d836c42 Task 3 — nsg-honeypot rules (attack surface + tight egress)
2fbf8aa Task 2 — isolated vnet-honeypot (no peering)
4ed7ea1 Task 1 — quota preflight + v2-azure env (Option A)
8d42bbb add official CrowdStrike→VT→Jira→Slack n8n template
3033fc7 CrowdStrike Falcon API reference for Plans 0B/0D
3993069 scaffold Phase 0A infra docs
```

## Plan 0A progress (guided portal execution — USER does portal steps, Claude commits docs)
- ✅ **Task 0** branch + scaffold · ✅ **Task 1** Total Regional vCPUs raised **20→28** · ✅ **Task 2**
  `vnet-honeypot` `10.66.0.0/24` (subnet `snet-honeypot` `10.66.0.0/27`), **peerings empty** ·
  ✅ **Task 3** `nsg-honeypot` (3 inbound RDP/SMB/web `Destination=Any`; 5 outbound tight egress).
- 🔶 **Task 4 (provision `vm-honeypot-win`) — PAUSED on VM size** (see next section).
- ⬜ **Tasks 5–10:** budget/spend-cap, clean snapshot, Sysmon, Splunk `honeypot` index + Universal
  Forwarder (+ open Splunk's NSG to the honeypot IP), e2e telemetry validation, finalize RUNBOOK.

## ⏸️ Task 4 VM size — decide after the AD-VM reclaim
Honeypot should be cheap B-series. **B2s (v1)** has BS-family quota (0/10) but is **capacity-restricted**
in Central US on this freshly-paid sub. **Bsv2** (B2als_v2 etc.) has capacity but **0 quota** (separate
family). Two options:
- **`Standard_B2als_v2`** (2 vCPU/4 GiB AMD, ~$38/mo) + one quick **BSv2-family** quota bump to 4 — cheapest.
- **`Standard_D2s_v4`** (2 vCPU) reusing **DSv4** quota freed by deleting the AD lab — no new request, ~$100+/mo.

VM settings (when ready): RG `rg-honeypot`, name `vm-honeypot-win`, image **`Windows Server 2022
Datacenter - x64 Gen 2`** (NOT Win11 — BYOL), **NIC NSG = None** (rely on subnet `nsg-honeypot`),
**Public IP = Standard + Static**, **Public inbound ports = None**, auto-shutdown **OFF**, no hardening.

## 🎯 ACTIVE NEXT ACTION — delete the abandoned AD lab (user is done with it)
- **DELETE `rg-sysadmin-lab`** — 4 VMs, all `Standard_D2s_v4` (2 vCPU each = **8 vCPU DSv4**), currently
  Stopped(deallocated): **`CLIENT01`** (20.9.35.71), **`CLIENT02`** (40.78.186.104), **`DC01`**
  (20.9.74.252), **`FS01`** (135.119.89.166). Deleting the whole resource group is fastest **if it holds
  only AD-lab resources — confirm with user.**
- **DO NOT TOUCH `rg-soc-v2-azure-central-us`** (the SOC stack the honeypot depends on):
  `vm-soc-v2-splunk` (10.0.0.5 / public **20.236.193.253**, D4s_v3), `vm-soc-v2-n8n` (10.0.0.6, D2s_v3),
  `vm-soc-v2-iris` (10.0.0.7, D2s_v3), `vm-soc-v2-win` (10.0.0.4, D4as_v7).
- **IMPORTANT:** every VM was deallocated yet quota read 20/20 → **deallocation did NOT free vCPU quota
  here. You must DELETE to reclaim quota + disk cost.** When deleting, **also check the boxes to delete
  OS disks, NICs, and public IPs** (Azure orphans them by default). Verify quota usage drops afterward.

## Key pipeline facts (Option A telemetry — decided)
- Honeypot is **UN-peered**. Universal Forwarder → Splunk's **public** IP **`20.236.193.253:9997`**,
  locked by Splunk's NSG to the honeypot's **static public IP** (add that inbound rule at Task 8; TLS
  recommended). Honeypot egress **denies `10.0.0.0/8`** (the SOC VNet) → no private route in. SOC VNet =
  `vm-soc-v2-win-vnet` `10.0.0.0/16`, RG `rg-soc-v2-azure-central-us`.

## ⚠️ Open issue (resolve when wiring Task 8 / Plan 0D)
SOC VMs auto-shutdown **11 PM Eastern**, but the honeypot runs 24/7. Splunk must be up to receive
telemetry (the UF queues overnight otherwise → delayed triage). Decide: run Splunk (+ n8n) 24/7 (more
cost) vs. accept batched overnight triage.

## After Plan 0A
- **0B — CrowdStrike Falcon:** 15-day trial, install sensor on the honeypot in **detect-only**
  (verify via `pattern_disposition_details` all-false), OAuth API creds (scopes Alerts:Read +
  Hosts:Read/Write), validate the `Contain` round-trip. See `crowdstrike-api-notes.md`.
- **0C — pipeline software (TDD):** verifier credibility-gate (SOP-RAG pattern), prompt/schema,
  lightweight eval harness (`golden/`, `eval.py`, `runs.jsonl`), run-log.
- **0D — n8n wiring:** fork `JSON/Analyze_Crowdstrike_detections.json` (Falcon detections poll, OAuth
  cred, two-step fetch, per-behaviour split, `continueOnFail`); build on the **Alerts API**; replace the
  Jira/Slack tail with Opus triage + verifier + enrichment roster (GreyNoise/AbuseIPDB/VT/URLscan) +
  Qdrant + DFIR-Iris + Discord + Falcon `Contain` + run-log; tight poll (not daily); fix the VT URL typo.
