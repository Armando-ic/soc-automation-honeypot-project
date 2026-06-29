# Phase 0D-2 — Falcon poller e2e validation (evidence)

Proof-of-work for the `falcon-alert-poller` n8n workflow (the Falcon Alerts-poll trigger grafted onto the
live `honeypot-triage` loop). Validated **2026-06-29** against the real us-2 EICAR behavioral detection.

> Sanitized: `composite_id`/CID/AID redacted to first/last 4. Full values live ONLY in the gitignored
> `Personal/honeypot-vm-creds.txt` + the VM's gitignored `grounding-service/.env`.

- **Workflow (source of truth):** `JSON/falcon-alert-poller.json` (regenerate: `python infra/honeypot/build_falcon_poller_workflow.py`).
- **Build runbook:** `falcon-poller-build.md` · **Confirmed schema:** `falcon-alerts-field-map.md`.
- **Watchdog (C.10) + `falcon-contain` (Section D): NOT built** — the watchdog was **deferred** (racy auto-lifter,
  low marginal value, can't run during the 23:00-ET n8n shutdown anyway). Stuck-contain recovery = the documented
  manual lift (`scripts/falcon-contain-roundtrip.ps1` lift leg).

## Setup

- Poll branch = 9 nodes: `Schedule Trigger(15m) → get_state → falcon_query → falcon_plan → IF has_new`
  —(true)→ `falcon_hydrate → falcon_map → Post+Collect → falcon_advance`; IF-false ends.
- `falcon_query` FQL = **`created_timestamp` alone** (host-scope dropped — n8n 2.21.7 can't transmit the FQL `+`
  AND; tenant is honeypot-only; Contain is AID-pinned). Proven `total:1`.
- Poller state seeded to `watermark=2026-06-29T00:00:00Z`, `seen:[]` so the lone EICAR alert is in-window.

## Evidence

### 1. `falcon_query` (read-only)
`GET /alerts/queries/alerts/v2?filter=created_timestamp:>='2026-06-29T00:00:00Z'&sort=created_timestamp|asc&limit=200`
→ `meta.pagination.total = 1`, `resources = ["306e…0772:ind:9134…5865:…995344"]` (the EICAR detection; its
embedded AID == the pinned honeypot AID).

### 2. Full poll run → empty-IOC → needs-human (NO 422)
EICAR (no `source_ips`) flowed the whole loop: source-aware **Parse Alert** consumed the Falcon body →
**empty-IOC guard** skipped AbuseIPDB/GreyNoise → triage → verifier → **needs-human**. The run-killing 422 that
behavioral (no-IOC) alerts used to cause **did not occur** — that was the whole point of the A′ edits.

Outputs:
- **DFIR-IRIS alert #245** `[NEEDS-HUMAN] FALCON — USER EXECUTION (INFORMATIONAL)` — severity **low**, MITRE
  **T1204 (User Execution)** (cited from the candidate set), **Enriched IOCs: _none_**, empty `src_ip` rendered
  cleanly, and the **Falcon console deep-link resolved** (`…/activity-v2/detections/306e…0772:ind:9134…5865:…995344`).
  No "Contain recommended" line (correct — `containRecommended` only fires on high/critical).
- **Discord** Needs-Human embed posted (matching title/host/empty-src_ip/"Verifier: NOT passed").
- `falcon_advance` → `watermark` advanced to `2026-06-29T15:10:32.158Z` (read from `timestamp`; the hydrated EICAR
  has no `created_timestamp`), `seen = ["306e…995344"]`.
- New `runs.jsonl` line written.

### 3. Idempotency (exactly-once triage)
Second full run: `falcon_query` still `total:1` (re-pulled by the inclusive `>=` filter) → `falcon_plan` deduped
EICAR via `seen` → `ids:[]` → **`IF has_new` false** → poll ends. **No duplicate Iris/Discord; state stable.**

### 4. Backend hardening — live smoke (deployed `soar-grounding-service` image)
After deploy (image rebuilt + recreated, `/health` ok), a scrambled 3-alert POST to `/falcon/map` returned items
**`created`-ascending** `b:2(01:00) → c:3(02:00) → a:1(03:00)` (#4), and the alert carrying `host_names:["other-host"]`
mapped to `ComputerName=other-host` while the others defaulted to `vm-honeypot-win` (#5). 23 pure `test_falcon.py`
tests green. Re-confirmed green on the all-green sweep.

### 5. Contain round-trip — `falcon-contain` (mechanism validated)
`JSON/falcon-contain.json` (Manual → resolve_host → contain_guard → contain → wait → status_contained → lift →
wait → status_normal → build_confirm → Discord). Fired manually 2026-06-29:
- **AID-pin held:** `contain_guard` resolved `vm-honeypot-win` → the pinned AID `9134…5865` (200); the contained
  device's `device_id` == that AID, `external_ip 128.203.185.25` (the honeypot).
- **`normal → contained → normal` observed:** `status_contained` = **`contained`** (≈21:50:01); after `lift`,
  `status_normal` = **`normal`** (v140, 22:00:46). Egress restored.
- **Safety logic proved itself:** the first run's 30s post-lift wait was shorter than CrowdStrike's lift-apply
  time, so `build_confirm` emitted the **RED "may still be CONTAINED"** alarm with the manual-lift command instead
  of a false all-clear. Fix applied: `wait_lift` 30s → **120s**.

### 6. Synthetic real-IP Contain-recommended path-validation (alert → "Contain recommended")
Closes the §"Not yet validated" Contain-demo gap deterministically, with a REAL AbuseIPDB-flagged IP and the
real pipeline — **no box compromise**, **recommend-only** (`falcon-contain` NOT fired). Clearly labeled
`[SYNTHETIC PATH-VALIDATION]`. Body of record: `infra/honeypot/synthetic-demo-body.json`.

- **Injection seam:** a single POST of a crafted Falcon-shaped body (`source:"falcon"`) to the **active
  `honeypot-triage` webhook** — the exact seam the poller uses after mapping — fired from inside the VNet
  (docker-host curl to `localhost:5678` on `vm-soc-v2-n8n`). Bypasses the poller → **poller `watermark`/`seen`
  untouched** (live state still `2026-06-29T15:11:34.51Z` / EICAR `seen`).
- **Real IP:** `2.57.121.25` — AbuseIPDB `abuseConfidenceScore` **100** (verified via `/check` pre-fire); the
  pipeline's own AbuseIPDB enrichment independently returned **`malicious`**.

**Run 282 (canonical artifact) → DFIR-IRIS #250** `FALCON — [SYNTHETIC PATH-VALIDATION] SUCCESSFUL BRUTE-FORCE
COMPROMISE (CRITICAL)`:
- `grounding-service` run `282`: **`verification_passed = true`**, all 10 deterministic checks **passed**
  (schema_valid, iocs_enriched_grounded, ioc_type_consistent, mitre_id_exists, mitre_name_match,
  mitre_tactic_valid, **severity_supported**, verdict_sourced, mitre_in_retrieved, enrichment_grounded).
- IOC `2.57.121.25` → **MALICIOUS (enrichment)**, sourced `abuseipdb`; MITRE **T1110.001 Password Guessing**
  (credential-access); `recommended_actions` fully populated (block IP / isolate host / reset Administrator / …).
- **Severity HIGH** — Opus *independently triaged* the (synthetic) Falcon "Critical" detection down to **high**,
  citing the honeypot's "limited blast radius and intended to be attacked." Falcon-severity-vs-analyst-triage
  divergence is realistic, not an error.
- `source=='falcon' && high` ⇒ Discord: **"⚠️ Contain recommended — run `falcon-contain` for vm-honeypot-win"**
  (`Verifier: passed`). This is the full **alert → triage → gate → Contain recommended** e2e.

**Advisory judge (second-opinion LLM; advisory only):** returns `needs_human` by design — it does **not** gate
`verification_passed` and does **not** surface to the Iris/Discord analyst view. The crafted body was hardened
across two fires to earn a clean judge read:
- **Run 281 / IRIS #249** (first fire): judge found **real contradictions** — `count:1` vs an alert_text claiming
  "sustained brute force", and an unsupported `T1021.001` (RDP / lateral-movement) citation lacking structured RDP
  evidence. Path proven, but the body was incoherent.
- **Run 282** (after an adversarial design+vet workflow redesigned the body to a coherent 487-fail→success
  credential-access chain, RDP dropped): judge's contradictions are **gone** — it calls the mapping "largely
  consistent… textbook password guessing" and the High rating "reasonable", offering only completeness nudges
  (also cite parent T1110 / add T1078). Advisory polish, not defect-finding.

**Takeaway:** the deterministic credibility gate auto-clears clear-cut cases (→ Contain recommended); the advisory
LLM judge always asks for a human — defense-in-depth, logged in `runs.jsonl`, invisible to the consumer view.

## Not yet validated / known-pending

- **Contain *demo* path (alert → "Contain recommended"):** ✅ **validated synthetically (§6)** — a labeled crafted
  high+IOC alert with a real AbuseIPDB-malicious IP drives the full gate → "Contain recommended" e2e. Still open:
  an **organic** real-attacker high-severity IOC alert (the now-active poller is the capture net); Falcon's
  honeypot detections so far are behavioral Execution with empty `source_ips`.
- **Watchdog (auto-lift):** deferred (racy; see HANDOFF). Stuck-contain recovery = the manual lift / the RED alarm.
- **Poller cron:** `falcon-alert-poller` left INACTIVE; activate when ready to run unattended.
