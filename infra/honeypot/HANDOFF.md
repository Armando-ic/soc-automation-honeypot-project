# Honeypot Agentic-SOC Upgrade — HANDOFF (2026-06-26)

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
- ✅ **Task 4 `vm-honeypot-win` DONE (2026-06-25)** — `Standard_B2als_v2`, **Windows Server 2022** Gen2,
  Standard security, public **`128.203.185.25`** (Static) / private `10.66.0.4`, NIC NSG=none, auto-shutdown
  OFF, running. Admin creds in gitignored `Personal/honeypot-vm-creds.txt`. (See `## VM` in README.)
- ✅ **Task 5 budget** `budget-honeypot-monthly` $60/mo (50/90/100% → `owner@example.com`).
- ✅ **Task 7 Sysmon** installed (SwiftOnSecurity v74 via Sysmon64 v15.21) + Defender RT disabled.
- ✅ **Task 8 UF** (10.4.0) forwarding to `20.236.193.253:9997`; Splunk `honeypot` index + 9997 receiver +
  NSG `allow-uf-9997-from-honeypot` (prio 1030) all live.
- ✅ **Task 9 e2e VALIDATED 2026-06-26** — `index=honeypot`: Security 6,130 + System 466 +
  **Sysmon (XmlWinEventLog) 3,330**. (Two bugs fixed: egress port typo `997`→`9997`; Sysmon
  `subscribeToEvtChannel errorCode=5` cleared via `wevtutil sl` + UF restart. See `RUNBOOK.md`.)
- ✅ **Task 6 snapshot** `snap-honeypot-clean` (`rg-honeypot`, full) — clean instrumented baseline.
- ✅ **Task 10 RUNBOOK** finalized (rebuild, lifecycle, malware, cost, hygiene, troubleshooting).

## 🟢 PLAN 0A COMPLETE (2026-06-26) — honeypot host telemetry → Splunk `honeypot` index, validated.

## ✅ Task 4 VM size — DECIDED (2026-06-24): `Standard_B2als_v2`
**`Standard_B2als_v2`** (2 vCPU / 4 GiB AMD, ~$38/mo) — cheapest 24/7 option. Family = **Basv2**
(usage/portal label; Quota REST resource name `standardBasv2Family`). **B2s (v1) ruled out** —
capacity-restricted in Central US on this freshly-paid sub. Fallback if Basv2 capacity is tight:
`Standard_D2s_v4` (~$100/mo) reusing the DSv4 quota freed below.

VM settings (Task 4 portal form): RG `rg-honeypot`, name `vm-honeypot-win`, image **`Windows Server 2022
Datacenter - x64 Gen 2`** (full Desktop Experience — NOT Win11/BYOL, NOT Server Core/Azure Edition/smalldisk),
size `Standard_B2als_v2`, **Public inbound ports = None**, VNet `vnet-honeypot` / subnet `snet-honeypot`,
**NIC NSG = None** (rely on subnet `nsg-honeypot`), **Public IP = Standard + Static**, auto-shutdown **OFF**,
no hardening. Admin password = STRONG (RDP service exposure is the surface, not a weak password) and lives
ONLY in the gitignored secrets file — never committed/echoed.

## ✅ DONE (2026-06-24) — AD-lab reclaim + Basv2 quota request
- **`rg-sysadmin-lab` DELETED** via `az group delete` (whole-RG delete took the 4 VMs + OS disks + NICs +
  public IPs in one shot — the per-VM orphan caveat didn't apply). Was 4× `Standard_D2s_v4` (CLIENT01/
  CLIENT02/DC01/FS01 = 8 vCPU DSv4, all deallocated). Verified it held ONLY AD-lab resources first.
- **Quota after delete: Total Regional 20 → 12 / 28** (16 free); **DSv4 8 → 0 / 10**. (Confirmed
  deallocation alone did NOT free quota — deletion did.)
- **SOC stack `rg-soc-v2-azure-central-us` untouched** (4 VMs verified present): `vm-soc-v2-splunk`
  (10.0.0.5 / public **20.236.193.253**), `vm-soc-v2-n8n`, `vm-soc-v2-iris`, `vm-soc-v2-win`.
- **Basv2 quota request submitted** (0 → 4) via Quota REST API — request id
  `ae2f78c6-cace-43d1-9c3a-fdf02e70e580`, InProgress at submit. **VM deploy is gated on this landing**
  (check: `az vm list-usage -l centralus --query "[?contains(localName,'Basv2')]" -o table`).

## 🎯 ACTIVE NEXT ACTION — Plan 0B (CrowdStrike Falcon), next session
Plan 0A is done (honeypot telemetry flowing into Splunk `honeypot`). Next:
- **0B — CrowdStrike Falcon:** 15-day trial; install the sensor on `vm-honeypot-win` in **detect-only**
  (verify via `pattern_disposition_details` all-false); OAuth API creds (Alerts:Read + Hosts:Read/Write);
  validate the `Contain` round-trip. See `infra/honeypot/crowdstrike-api-notes.md`. Sensor download +
  install can be done via `az vm run-command` (no RDP needed) — see RUNBOOK "Remote ops note".
- Then **0C** (verifier + eval harness, TDD) and **0D** (n8n wiring; fork `JSON/Analyze_Crowdstrike_detections.json`).
- Optional 0A polish: install `Splunk_TA_microsoft_sysmon` on the Splunk indexer/SH for nicer Sysmon
  field extraction (not blocking — raw XML already lands in `honeypot`).

### Useful facts for next session
- Honeypot admin: RDP/Run-Command to `128.203.185.25`, user `analyst`, pw in `Personal/honeypot-vm-creds.txt`.
- Splunk auto-shuts 23:00 ET; START `vm-soc-v2-splunk` (portal) before expecting live ingestion. UF queues meanwhile.
- I can run honeypot-VM commands via `az vm run-command invoke -g rg-honeypot -n vm-honeypot-win` (as SYSTEM, no RDP).
Note: provisioning was done via `az` CLI (user-authorized), not the portal — but on-VM + Splunk steps still need the USER.

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
