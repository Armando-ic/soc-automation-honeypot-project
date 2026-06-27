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

## 🎯 CURRENT STATE (2026-06-27) — 0A done · 0C ✅ BUILT · 0D-1a ✅ BUILT (grounding-service) · 0D-1b/0D-2 next · 0B trial APPROVED, user setting up
Plan 0A done. Plan 0C **COMPLETE**. **Plan 0D-1a ✅ BUILT this session** — subagent-driven (8 TDD tasks + 1
cleanup commit, fresh implementer + reviewer per task, opus final whole-branch review). The `grounding-service/`
FastAPI package now exists: 23 tests green/pristine, commits `ac1e8d8..71720f0` on ai-upgrade (NOT pushed; user
chose "keep branch as-is"). Final review verdict: ready to merge. See the Plan 0D block for details + carry-forwards.
**Falcon trial APPROVED 2026-06-27 — USER is setting up the Falcon account** (0B Tasks 2–7, hands-on).
**Next actions for a fresh instance:** (1) author **Plan 0D-1b** (n8n wiring — hands-on checklist; the
grounding-service it calls now exists; MUST carry the 2 Important items in the Plan 0D block); (2) once 0B is
validated, author **0D-2** (Falcon Alerts trigger + Contain). Both spec'd in the 0D design doc §7.

**Plan 0B — CrowdStrike Falcon — trial APPROVED 2026-06-27, USER setting up account.**
- Plan: `docs/superpowers/plans/2026-06-26-honeypot-phase0b-crowdstrike-falcon.md` (PARENT workspace).
- Falcon 15-day trial **APPROVED 2026-06-27** (submitted 2026-06-26, no-CC self-service). **USER is setting up
  the account + doing Tasks 2–7 HANDS-ON via RDP** — condensed checklist in `scratchpad/falcon-day2-quickstart.md`.
  (Hands-on, NOT `az run-command` — user "learn by doing" preference; memory `feedback_prefers_hands_on_doing`.)
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
**Plan 0D — SOAR wiring — 0D-1a ✅ BUILT 2026-06-27; 0D-1b/0D-2 designed (spec §7), not built.**
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
