# Honeypot Agentic-SOC Upgrade — HANDOFF (2026-06-29)

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

## 🎯 CURRENT STATE (2026-06-29) — 0A done · 0C ✅ BUILT · 0D-1a ✅ BUILT · 0D-1b Phase 1 ✅ DONE & LIVE · **0D-1b Phase 2 (Wire) ✅ COMPLETE — the loop is LIVE-TRIGGERED** · **0B Falcon ✅ COMPLETE (2026-06-29): detect-only sensor + OAuth API + Contain→Lift all VALIDATED (`normal→contained→normal`, `pattern_disposition_details` all-false) → `falcon-validation.md`; Task 8 lifecycle docs in RUNBOOK/README; trial keep/drop reminder scheduled 2026-07-11 09:00 ET (routine `trig_01VGbabpwThgahchN54z4GTy`). ⚠️ API secret was pasted in chat → ROTATED. **0D-2 IN PROGRESS (2026-06-29) — plan written; Tasks 0–7 DONE (Python backend + 5 routes + builder A′ edits + deploy + live smoke + honeypot-triage re-imported & both smokes green); building the n8n `falcon-alert-poller` next. ▶ See the "## 🟢 0D-2 IN PROGRESS" block below for the exact resume point.**

## 🟢 0D-2 IN PROGRESS (2026-06-29) — Falcon Alerts poll + human-fired Contain. Tasks 0–7 DONE; building the n8n poller.

**Read-first for 0D-2:**
- **Plan (PARENT):** `docs/superpowers/plans/2026-06-29-honeypot-phase0d2-falcon-trigger-contain.md` (14 tasks).
- **Spec (PARENT):** `docs/superpowers/specs/2026-06-29-honeypot-phase0d2-falcon-trigger-contain-design.md` (approved).
- **n8n build runbook (THIS REPO):** `infra/honeypot/falcon-poller-build.md` — node-by-node for the poller + AID-pinned `falcon-contain` + watchdog. **Build from this.**
- **CONFIRMED us-2 schema (THIS REPO):** `infra/honeypot/falcon-alerts-field-map.md` — the §10 checks, resolved live.

**Commits (ai-upgrade, pushed to `honeypot` remote): `008e49f..c78af38`.** 48 grounding-service tests green.

**✅ DONE (Tasks 0–7):**
- **Python backend** = `grounding-service/grounding_service/falcon.py` (pure: `load/save_state`, `select_new_alert_ids`,
  `advance_state` contiguous-prefix watermark, `map_alert`, `alert_created`, `composite_id_of`, `select_contain_aid`)
  + **5 routes in `app.py`**: `GET /falcon/state`, `POST /falcon/{plan,map,advance,contain-guard}`. TDD.
- **honeypot-triage A′ edits** (Task 5) in `build_honeypot_triage_workflow.py` → regenerated `JSON/honeypot-triage.json`
  (18 nodes: source-aware Parse Alert, `Has IOC` empty-IOC guard, Extract Result `source`/`console_link` + Contain line).
- **Task 0 §10 confirmed LIVE on us-2 + reconciled into the code (CRITICAL — the 0B doc was wrong):**
  - Watermark **read = `created_timestamp` then `timestamp`** (real object has `timestamp`+`updated_timestamp`, **no `created`**); **FQL key = `created_timestamp`**.
  - **host-scope `device.hostname:'vm-honeypot-win'` is filterable.** Attacker IP = **`source_ips[]`** (array; empty on behavioral alerts; **unconfirmed-populated** — no credential-access alert exists in the tenant yet).
  - **`composite_id` is NOT returned** = `origin_cid` + `:` + `id`. **No top-level `filename`/`cmdline`** → use `name` + `sha256`/`md5` (skip all-zero hash).
  - **Honeypot AID = `11111111111111111111111111111111`** (in `Personal/honeypot-vm-creds.txt` + the VM `.env` `FALCON_PINNED_AID`).
- **Task 6 deploy:** `falcon.py`+`app.py`+`docker-compose.yml`(`FALCON_*` env) synced to `/root/soc-src` (base64 over az run-command),
  container rebuilt, `FALCON_PINNED_AID` set in `/root/soc-src/grounding-service/.env`, all 5 routes **smoke-validated live** on the real EICAR schema.
- **Task 7:** `honeypot-triage` re-imported (18 nodes), creds re-bound, **Discord URL re-set** (it reverts to `REPLACE_ME` on import → 405 if not),
  re-activated. **Both smokes GREEN:** Splunk path → passed + green Discord (no Contain line); Falcon empty-IOC path → **needs-human, NO 422** (the guard works).

**Live state the fresh instance must know (NOT in git):**
- **VMs `vm-soc-v2-n8n` + `vm-soc-v2-splunk` are RUNNING** (started this session). ⚠️ **Deallocate if not resuming today:**
  `az vm deallocate -g rg-soc-v2-azure-central-us -n vm-soc-v2-n8n` (and `vm-soc-v2-splunk`).
- grounding-service routes are **live**; poller watermark was **RESET to `2026-06-29T00:00:00Z`, `seen:[]`** for testing
  (`/data/falcon-poller-state.json`) so the lone EICAR alert is visible. It advances past EICAR after the first successful poll — fine.
- n8n: `honeypot-triage` is live + active. **New workflow `falcon-alert-poller` started** — built so far: `Schedule Trigger`(15m) → `get_state` → `falcon_query`.
- n8n credential **"Crowdstrike Falcon Account"** (type **CrowdStrike OAuth2 API**, URL `https://api.us-2.crowdstrike.com`) created.
  Its connection test shows **"unsuccessful" — EXPECTED** (`honeypot-soar` lacks `usermgmt:read`); it still works for Alerts/Hosts.

**▶ RESUME HERE (Task 8a — the poller's `falcon_query` FQL fix, then continue):**
1. **Fix the `falcon_query` filter.** Proven live: `device.hostname:'vm-honeypot-win'` ALONE and `created_timestamp:>='2026-06-29T00:00:00Z'` ALONE
   each return the EICAR id (total:1), but the **combined `A+B` (FQL AND) via n8n "Send Query Parameters" returns 0** — n8n is mangling the `+` AND operator.
   **Fix options:** (a) put the whole query string in the **URL field** using **`%2B`** for the AND (`…?filter=created_timestamp:>='{{ $('get_state').item.json.watermark }}'%2Bdevice.hostname:'vm-honeypot-win'&sort=created_timestamp|asc&limit=200`),
   or (b) since the tenant is **honeypot-only**, filter on **`created_timestamp` alone** and drop host-scope (Contain stays AID-pinned; note the re-enroll caveat). Re-run → expect `total:1`.
2. **Finish the poller** per `falcon-poller-build.md` **Section C**: `falcon_plan` (POST `/falcon/plan`) → `IF has_new` → `falcon_hydrate`
   (POST Falcon `alerts/entities/alerts/v2`) → `falcon_map` (POST `/falcon/map`) → **`Post+Collect`** Code node (the `this.helpers.httpRequest`
   loop that POSTs each body to `http://10.0.0.6:5678/webhook/honeypot-triage`, oldest-first, `break` on first failure) → `falcon_advance` (POST `/falcon/advance`).
   Execute → the EICAR alert flows to **needs-human** (empty-IOC), state advances; re-run → nothing new (idempotency).
3. **Watchdog** (Section C.10) + **`falcon-contain`** (Section D, AID-pinned via `/falcon/contain-guard`).
4. **Task 11 e2e** (empty-IOC ✓ already, Contain-path needs a credential-access/IOC alert — may need to generate one), **Task 12** evidence
   (`infra/honeypot/falcon-0d2-validation.md`), **Task 13** export sanitized poller+contain JSON + `RUNBOOK`/`README`/this HANDOFF + **deallocate VMs**. Phase 0 complete.

**Open (non-blocking):** real console deep-link URL for `CONSOLE_LINK_TEMPLATE`; confirm `source_ips` populated on a real credential-access alert.
**Format note (memory `feedback_handson_instruction_format`):** give the USER hands-on steps with a "Where:" machine header + numbered commands.

> ### 🟢 0D-1b Phase 2 (Wire) ✅ COMPLETE — n8n pipeline + Splunk auto-trigger BUILT + e2e VALIDATED (2026-06-28 wire; **2026-06-29 Task 7 live-trigger**)
> Spec `docs/superpowers/specs/2026-06-28-honeypot-phase0d1b-phase2-wire-design.md`; plan
> `docs/superpowers/plans/2026-06-28-honeypot-phase0d1b-phase2-wire.md` (both PARENT, approved). Build method =
> **fully hands-on** (USER built it in n8n; final shape captured as an importable JSON), trigger = **brute-force-only**
> (Splunk 4625 per-src_ip), notify = **Discord**, live judge = **wired**.
> **DONE (commits `66c43ed`→`366f702` on `honeypot/ai-upgrade`):** Task 1 CF#1 (`/verify` logs+gates false on
> verifier exception, never 500; 25 tests green) · Task 2 forked + hardened Opus prompt `triage-verifier/prompts/triage-honeypot.md`
> (mandates all 9 fields) · Task 3 build runbook `infra/honeypot/honeypot-triage-build.md` · Task 4 VM rebuild —
> CF#1 baked, Qdrant 846, **live ClaudeJudge active** · Task 5 GreyNoise + Discord creds · Task 6 the 17-node
> `honeypot-triage` workflow (importable **`JSON/honeypot-triage.json`**, sanitized) — Webhook→Parse→AbuseIPDB+
> GreyNoise→`/normalize`→`/retrieve`→Opus(`claude-opus-4-8`,`submit_triage_result`)→Extract→`/verify`→Gate→
> [PASS: Iris+Discord][FAIL: Needs-Human Iris+Discord].
> **✅ e2e VALIDATED LIVE:** happy path `run_id 241` `verification_passed:true` — all 8 deterministic checks pass,
> **both deferred checks live+pass** (`mitre_in_retrieved`, `enrichment_grounded`), live judge `needs_human`
> (advisory), Iris alert + green Discord embed + `runs.jsonl` line. **Failure path proven** (`run_id 238/240` →
> needs-human Iris+Discord). CF#2 IOC canonical-form held (IP matched across `iocs`/`iocs_enriched`/`enrichment_results`).
> **Fixes found during e2e (all committed):** (a) n8n "Using JSON" body needs `JSON.stringify(...)` not a raw `={{ {…} }}` object;
> (b) Opus reliably drops the trailing `investigation_notes` even when mandated → Extract Result now defensively fills
> all 9 required fields (substantive checks still run on the model's real values); (c) un-pin the Opus node between
> test runs or n8n replays stale output.
> **Gotchas (documented):** live-judge `.env` MUST be at `grounding-service/.env` (Compose ignores a repo-root `.env`);
> `/root/soc-src` is a **transferred (non-git) tree** — sync changed files via base64 over `az vm run-command`;
> `run_meta` tokens log as 0 (langchain node doesn't expose usage — accepted).
> **✅ Task 7 — Splunk saved-search DONE & e2e-VALIDATED (2026-06-29):** saved search
> `Honeypot - RDP/SMB brute force (external)` is LIVE — cron `*/15`, trailing 30 min, **Balanced** threshold
> `count>=2` per `src_ip`, `sort -count | head 1` (Splunk's webhook posts only the first result), per-`src_ip` 1h
> throttle (Trigger=For each result), webhook → the n8n **PRIVATE** URL `http://10.0.0.6:5678/webhook/honeypot-triage`
> (Splunk 10.0.0.5 → n8n 10.0.0.6). The original `≥10/5min` was wrong for this honeypot — it gets slow distributed
> credential-stuffing (85 distinct IPs/24h, ≤2 per 5 min). **Field facts:** `src_ip` IS extracted (= `Source_Network_Address`),
> `user`=`Administrator`, `ComputerName`=`vm-honeypot-win`, ⚠️ `src`=`workstation` is a decoy (NOT an IP). Proven via
> `| sendalert webhook` → IRIS alert **#230** + green Discord (src_ip 156.239.41.77, T1110.001, HIGH) + `runs.jsonl`
> **`run_id 243` `verification_passed:true`** (13 lines now). Full finalized SPL + alert form + on-demand `sendalert`
> test + the `| rest` config-verify search are in **runbook §D** (rewritten this session).
> **REMAINING / NEXT:** **OPTIONAL** — add the bounded one-shot **re-ground** branch (omitted from the importable JSON
> for reliability; FAIL currently goes straight to needs-human — safe + logged); also an OPTIONAL cosmetic fix to C.4's
> `splunk_link` rewrite (the IRIS deep-link shows internal host `vm-soc-v2-splunk:8000` — add `.replace('vm-soc-v2-splunk','20.236.193.253')`).
> Then **0D-2** (Falcon trigger + Contain) within the trial window once 0B is validated.
> **VMs `vm-soc-v2-n8n` + `vm-soc-v2-splunk` STARTED this session — DEALLOCATE at end (cost-safe):
> `az vm deallocate -g rg-soc-v2-azure-central-us -n <vm>` both; everything auto-resumes + judge survives reboot on next start.**
> The importable workflow is `JSON/honeypot-triage.json` (regenerate via `python infra/honeypot/build_honeypot_triage_workflow.py`).
Plan 0A done. Plan 0C **COMPLETE**. **Plan 0D-1a ✅ BUILT** (subagent-driven, 23 tests, commits
`ac1e8d8..71720f0`, ready-to-merge). **0D-1b was SPLIT into Phase 1 (Deploy) + Phase 2 (Wire).**
**Phase 1 (Deploy) ✅ DONE & VALIDATED LIVE this session (2026-06-28)** — grounding-service + Qdrant now run
as containers on `vm-soc-v2-n8n` (network `soar-net`; the existing n8n container attached via `docker network
connect`; both new containers `--restart unless-stopped`). ATT&CK ingested (**846 techniques**), and the n8n→service
path is proven: `/health` ok, `/retrieve` returns real bge-small results (e.g. "rdp brute force" → RDP Hijacking
/ Remote Desktop Protocol), `/normalize` + `/verify` work (gate live, both deferred checks pass, StubJudge,
run-log written), and **VM deallocate→start reboot-survival confirmed** (containers auto-resume, volume persists
846). The VM is left **deallocated** (cost-safe); next start auto-resumes everything.
> ### 🟡 0B — CrowdStrike Falcon — IN PROGRESS (2026-06-29): Tasks 2–5 built; verify + Tasks 6–8 remain
> Executing `docs/superpowers/plans/2026-06-26-honeypot-phase0b-crowdstrike-falcon.md` (PARENT) via
> **superpowers:executing-plans**, USER hands-on. **Full step-by-step + gotchas + proof-of-work:
> `infra/honeypot/falcon-setup-walkthrough.md`** (written this session).
> **Tenant:** cloud **us-2**, base `https://api.us-2.crowdstrike.com`. Trial **expires 2026-07-13** (~14d left
> on 2026-06-29); keep/drop checkpoint ~2026-07-12. Secrets (Client ID/Secret, CID) in `Personal/honeypot-vm-creds.txt` ONLY.
> **✅ DONE this session (commits `500976b`, `843337f` + tonight's doc commit):**
> - **Task 2** — API client `honeypot-soar` (scopes Alerts:R/W + Hosts:R/W + Event streams:R); base URL us-2 recorded.
> - **Task 3** — sensor **7.38.21003.0** on `vm-honeypot-win` (csagent RUNNING; ext IP 128.203.185.25 confirmed).
>   NSG checked: `allow-web` (443→Internet, prio 1020) covers the sensor — **no NSG change**.
> - **Cleanup** — a personal Win11 PC (`PERSONAL-WIN11`) had auto-enrolled in the trial tenant → **UNINSTALLED**
>   (maintenance token) so the tenant is honeypot-only (else a tenant-wide 0D-2 alert poll would sweep it in / could Contain it).
> - **Task 4** — Insight XDR enabled; **EDR (Endpoint detections) views visible**. (Alerts API 200 smoke test folds into Task 6's pull.)
> - **Task 5** — host group `hg-honeypot` (Dynamic, hostname=`vm-honeypot-win`) + policy `honeypot-detect-only`
>   **BUILT + assigned**: all prevention OFF, ML Detection sliders AGGRESSIVE, ⭐ behavioral enrichments UP
>   (Cloud-based anomalous process execution → Aggressive, Extended user mode data visibility → Aggressive,
>   Retrospective detections ON). Policy doc reconciled to the real console: `infra/honeypot/falcon-detect-only-policy.md`.
> - **⚠️ Gotcha (documented):** "Script-based execution visibility" forces "Quarantine & security center
>   registration" ON (= quarantine subsystem) → **Cancel it / keep quarantine OFF** for detect-only.
> **▶ RESUME HERE:**
> 1. ✅ **Task 5 DONE (2026-06-29)** — policy `honeypot-detect-only` confirmed **Applied: 1** (Date applied
>    2026-06-28 23:57:53; host Last seen 2026-06-29 10:54).
> 2. ✅ **Task 6 DONE (2026-06-29)** — detect-only VALIDATED. EICAR didn't trip Falcon's ML (it's behavioral,
>    EICAR is a signature artifact); instead the behavioral engine convicted the PowerShell that wrote it →
>    Informational `Execution/User Execution T1204`, `Source: Falcon Insight` (EDR), `pattern_disposition: 0`,
>    **all 28 `pattern_disposition_details` booleans false**. Evidence: `infra/honeypot/falcon-validation.md`.
>    (API pull was run on a LOCAL machine, NOT the honeypot — secret never exposed.)
> 3. ✅ **Task 7 DONE (2026-06-29)** — Contain→Lift round-trip clean (`normal→contained→normal`, final `normal`)
>    via `scripts/falcon-contain-roundtrip.ps1` from a LOCAL machine. **0B done-when met.** ⚠️ During setup the
>    `honeypot-soar` Client ID + Secret were pasted in plaintext → **secret RESET** in the console (same Client
>    ID, new secret) + creds file updated + session/PSReadline history cleared. Evidence: `falcon-validation.md`.
> 4. ✅ **Task 8 DONE (2026-06-29)** — Falcon lifecycle/off-board + trial keep/drop matrix in `RUNBOOK.md`;
>    README synced; one-time trial keep/drop reminder scheduled for **2026-07-11 09:00 ET** (routine
>    `trig_01VGbabpwThgahchN54z4GTy` → https://claude.ai/code/routines/trig_01VGbabpwThgahchN54z4GTy). **0B COMPLETE.**
> 5. **0D-2 ◀ RESUME (DESIGNED + reviewed + APPROVED 2026-06-29)** — brainstorm → spec → 5-lens adversarial review
>    (Workflow, 21 confirmed findings, all folded in) → revised spec, all approved. **Spec (PARENT):**
>    `docs/superpowers/specs/2026-06-29-honeypot-phase0d2-falcon-trigger-contain-design.md`.
>    **Next = run `superpowers:writing-plans` on the approved spec, THEN execute (hands-on n8n; start the SOC VMs).**
>    ⚠️ The plan MUST open with the spec's §10 **blocking pre-build checks**: one live `GET /alerts/queries/alerts/v2`
>    on us-2 to confirm field names — `created` vs `created_timestamp` (the validated sample showed `created`),
>    the host-scope filter, the attacker-source-IP field, and the console deep-link URL — several gate the build.
>    Locked decisions (§9): **A′** = the Falcon poller emits the EXISTING Splunk-shaped body
>    (`{search_name, results_link, result:{src_ip,user,ComputerName,count}}`) + additive `source`/`alert_text`/
>    `console_link` (NOT a new envelope); **AID-pinned** Contain (resolve hostname→AID, hard-stop unless ==1 match
>    AND AID == the pinned honeypot AID `9134…5865`); **empty-IOC guard** (skip AbuseIPDB/GreyNoise when `src_ip`
>    is empty — fixes a run-killing 422 on behavioral alerts); triage severity read from **Extract Result** (the
>    `/verify` report has none); durable watermark/seen in a **VM file** (n8n static data is wiped by the
>    regenerate-and-reimport build loop); **containment watchdog** (safe auto-Lift of a stuck contain); per-poll
>    cap + aggregation; `>=` watermark + single composite_id dedup; dropped `severity_hint`. Contain demo must use
>    a **credential-access (RDP brute-force) / IOC-bearing** alert (the verifier's `severity_supported` won't pass
>    a no-IOC Execution alert at High).

**Plan 0B — CrowdStrike Falcon — IN PROGRESS (live state = the 🟡 0B block above). Background below.**
- Plan: `docs/superpowers/plans/2026-06-26-honeypot-phase0b-crowdstrike-falcon.md` (PARENT workspace).
  Walkthrough/proof-of-work: `infra/honeypot/falcon-setup-walkthrough.md`.
- Falcon 15-day trial activated ~2026-06-28 (expires 2026-07-13). **Hands-on via RDP/console**, NOT
  `az run-command` — user "learn by doing" preference; memory `feedback_prefers_hands_on_doing`. (The earlier
  `scratchpad/falcon-day2-quickstart.md` checklist no longer exists — the walkthrough doc supersedes it.)
- **Research corrected the spec (see the rewritten `crowdstrike-api-notes.md`):** legacy `/detects/*` API is
  DEAD (404 since 2025-09-30) → build on the **Alerts API**; one API client, scopes **Alerts:R/W + Hosts:R/W +
  Event streams:R**; real EDR = the free **Insight XDR** module enabled in-trial (the trial defaults to NGAV-only
  Go modules); **sustained EDR ≈ Enterprise $185/dev/yr, NOT Go $60** (Go has no EDR); detect-only = a console
  **prevention-policy build** (verify `pattern_disposition_details` all-false); the sensor is **443-only** → the
  existing `allow-web` NSG already covers it (no NSG change). Decisions also recorded in honeypot spec §11.12.
- Already committed (0B Task 0 + prep): `falcon-detect-only-policy.md`, `scripts/falcon-contain-roundtrip.ps1`.
  0B done-when: detect-only sensor + OAuth API + `Contain`→`Lift` captured. Keep/drop deferred to ~trial day 14.

**Plan 0C — Triage verifier + eval harness — ✅ COMPLETE (built 2026-06-26, subagent-driven).**
- Spec: `docs/superpowers/specs/2026-06-26-triage-verifier-eval-design.md` (PARENT).
- Plan: `docs/superpowers/plans/2026-06-26-honeypot-phase0c-triage-verifier.md` (PARENT) — all 13 tasks (0–12)
  executed via `superpowers:subagent-driven-development` (fresh implementer + task reviewer per task, opus
  final whole-branch review). Built the standalone package **`triage-verifier/`** in the repo: pure offline
  verifier (8 deterministic checks + advisory judge that never auto-approves + 2 deferred Qdrant hooks
  reporting NOT_APPLICABLE until 0D) + 14 golden fixtures + `eval.py` gate. **35 pytest tests pass; `eval.py`
  14/14 matched, exit 0.**
- **Commits:** Plan 0C range `2d3eb88..80f1c9d` on `ai-upgrade` (13 task commits + 1 final-review hardening
  fix `b134f20` + 1 gitignore cleanup `80f1c9d`). Final-review fix: decoupled `ioc_type_consistent` from
  absent IOCs (grounding owns "absent") + tightened `eval.py` to enforce exactly-one-failure per negative
  fixture (spec §8). Per-task ledger: `.superpowers/sdd/progress.md` (gitignored scratch).
- **0D carry-forward (latent, 0C makes no live call):** `ClaudeJudge` prompt embeds `str(result)` (untrusted
  LLM output) — when 0D wires the live call, keep judge status hardcoded `NEEDS_HUMAN` + treat judge notes as
  untrusted display text. Also: `triage-verifier/` has no black/isort/mypy gate wired (configured in
  pyproject but not enforced); a few plan-mandated cosmetic import-order/dead-name nits remain (a one-shot
  `isort`+`black` pass would normalize them).
**Plan 0D — SOAR wiring — 0D-1a ✅ BUILT · 0D-1b Phase 1 (Deploy) ✅ DONE & LIVE 2026-06-28 · Phase 2 (Wire) + 0D-2 next.**
> **0D-1b Phase 1 (Deploy) artifacts/state:** spec `docs/superpowers/specs/2026-06-27-honeypot-phase0d1b-deploy-design.md`,
> plan `docs/superpowers/plans/2026-06-27-honeypot-phase0d1b-phase1-deploy.md` (both PARENT). Code reached the VM
> via a NEW **private** GitHub repo **`Armando-ic/soc-automation-honeypot-project`** (remote `honeypot`; the
> public `Armando-ic/SOC-Automation-Project` = origin, untouched; secrets audit gitleaks-clean over 169 commits).
> On `vm-soc-v2-n8n`: `docker network soar-net`; containers `qdrant` + `grounding-service` (built from
> `grounding-service/Dockerfile` + `docker-compose.yml`, committed); n8n attached via `docker network connect`.
> Source is at `/root/soc-src` on the VM. **Ingest fix this session (commit `dc43396`):** the one-shot embed of
> the 846-technique corpus OOM-killed (~7 GiB) on the 8 GiB VM → `upsert_techniques` now batches (batch_size=64);
> 23 tests still green. To re-ingest/refresh: `docker exec grounding-service python scripts/ingest_attack.py`.
> **Live judge still deferred** — `ANTHROPIC_API_KEY` is NOT set on the VM (StubJudge); Phase 2 wires it (one-line
> container env + recreate). **NOTE:** Phase-1 commits (`a9bad14`, `1fd83ac`, `dc43396`) were pushed to `honeypot`
> but the HANDOFF commit for this update is local-only unless pushed.
- Spec: `docs/superpowers/specs/2026-06-27-honeypot-phase0d-soar-wiring-design.md` (PARENT) — **approved.**
- 0D-1a plan: `docs/superpowers/plans/2026-06-27-honeypot-phase0d1a-grounding-service.md` (PARENT) — **8 TDD
  tasks (0–7), complete code, self-reviewed; ready to execute subagent-driven. NOT started.**
- **Locked design decisions (spec §9):** (1) **split** 0D into **0D-1** (Splunk-honeypot-triggered enriched
  triage path, build NOW, no CrowdStrike) + **0D-2** (Falcon Alerts-poll trigger + `Contain`, deferred until
  0B is set up); (2) verifier runs as a **FastAPI microservice** (Python package stays source of truth);
  (3) Qdrant in 0D-1 = **MITRE RAG only**, repeat-noise throttled at the Splunk saved-search, defer
  incident-similarity; (4) **co-locate** Qdrant + FastAPI on the existing **`vm-soc-v2-n8n`** (loopback; NO
  new VM, NO protected-RG change); (5) **deterministic up-front enrichment** feeds both Opus and the verifier
  (non-circular ground truth); (6) one `/retrieve` call = authoritative `retrieved`; (7) triage model
  **`claude-opus-4-8`**, `submit_triage_result` schema unchanged; (8) bounded re-ground = one retry then
  needs-human; (9) Discord webhook replaces Slack, `/verify` writes the run-log, batched overnight accepted.
- **0D-1a = the grounding-service ✅ BUILT** (`grounding-service/` package, depends on `triage-verifier`):
  FastAPI `/retrieve` (Qdrant ATT&CK RAG → verifier's `retrieved`), `/verify` (wraps 0C verifier + run-log +
  judge w/ StubJudge fallback; flips the 2 deferred checks live), `/normalize` (enrichment → verdict). Offline
  suite **23 tests green/pristine**. Commits `ac1e8d8..71720f0` (8 tasks + cleanup) on ai-upgrade. Final opus
  review: ready to merge. Per-task ledger archived at `.superpowers/sdd/progress.md` (gitignored scratch).
  **Accepted deviations (all sound):** retriever uses `query_points` (qdrant-client 1.18 removed `.search()`);
  `_build_retriever` passes `check_compatibility=False` (eager compat-check would hang at the module-level
  `app=build_default_app()` import); pyproject `filterwarnings` mutes the upstream Starlette TestClient warning.
  **Deploy:** co-locate on `vm-soc-v2-n8n` — `docker run qdrant` (:6333 loopback), `scripts/ingest_attack.py`
  to populate ATT&CK, `uvicorn grounding_service.main:app` (:8000); n8n calls it over loopback.
  **⚠️ Two Important carry-forwards INTO 0D-1b** (both fail-safe today, they live in the n8n/integration layer):
  (1) `/verify` should try/except the verifier call and **log + gate `verification_passed:false`** on a verifier
  exception instead of returning 500 (preserves spec §5.5 "every event logged, never dropped"); (2) pin **ONE
  canonical IOC-value form** shared by the `/normalize` enrichment key AND Opus `iocs_enriched[].value`, else the
  `enrichment_grounded` check false-FAILs on case/defang/CIDR string drift (README limitation already notes this).
- **0D-1b (n8n wiring) + 0D-2 (Falcon)** — authored AFTER 0D-1a is built: 0D-1b is a **hands-on** n8n checklist
  (Splunk saved-search trigger → enrichment HTTP nodes → `/normalize` → `/retrieve` → Opus → `/verify` → gate
  → Iris + Discord + run-log); 0D-2 grafts the Falcon Alerts-poll trigger + `Contain` (verifier-passed +
  high-severity + human-gated) onto the same path. Both spec'd in the 0D design doc §7.

### Useful facts
- Honeypot admin: RDP `128.203.185.25`, user `analyst`, pw ONLY in `Personal/honeypot-vm-creds.txt` (never echo/commit).
- Splunk auto-shuts 23:00 ET; START `vm-soc-v2-splunk` (portal) before expecting live ingestion. UF queues meanwhile.
- `az vm run-command invoke -g rg-honeypot -n vm-honeypot-win` runs PowerShell as SYSTEM (no RDP) — kept as a FALLBACK; default to hands-on.
- az CLI authenticated (sub `3718c265-...`, `owner@example.com`). On Git Bash, prefix az calls passing full `/subscriptions/...` IDs with `MSYS_NO_PATHCONV=1`.
- **rg-soc-v2-azure-central-us (Splunk/n8n/Iris) is PROTECTED** — explicit consent before any security-loosening change; `rg-honeypot` is the free-to-modify sandbox.

## Key pipeline facts (Option A telemetry — decided)
- Honeypot is **UN-peered**. Universal Forwarder → Splunk's **public** IP **`20.236.193.253:9997`**,
  locked by Splunk's NSG to the honeypot's **static public IP** (add that inbound rule at Task 8; TLS
  recommended). Honeypot egress **denies `10.0.0.0/8`** (the SOC VNet) → no private route in. SOC VNet =
  `vm-soc-v2-win-vnet` `10.0.0.0/16`, RG `rg-soc-v2-azure-central-us`.

## ⚠️ Open issue (resolve when wiring Task 8 / Plan 0D)
SOC VMs auto-shutdown **11 PM Eastern**, but the honeypot runs 24/7. Splunk must be up to receive
telemetry (the UF queues overnight otherwise → delayed triage). Decide: run Splunk (+ n8n) 24/7 (more
cost) vs. accept batched overnight triage.

## Roadmap after 0A (0B & 0C now PLANNED — CURRENT STATE above is authoritative)
- **0B — CrowdStrike Falcon:** plan written; trial running. (The earlier "/detects API · Alerts:Read+Hosts:RW
  · az-run-command install" framing is **SUPERSEDED** — see CURRENT STATE + the rewritten `crowdstrike-api-notes.md`.)
- **0C — verifier + eval (TDD):** ✅ BUILT (`triage-verifier/`, 35 tests + `eval.py` 14/14; range `2d3eb88..80f1c9d`).
- **0D — n8n wiring:** fork `JSON/Analyze_Crowdstrike_detections.json`; build on the **Alerts API**; replace the
  Jira/Slack tail with Opus triage + the 0C verifier + enrichment roster (GreyNoise/AbuseIPDB/VT/URLscan) +
  Qdrant + DFIR-Iris + Discord + Falcon `Contain` + run-log; tight poll (not daily); fix the VT URL typo.
