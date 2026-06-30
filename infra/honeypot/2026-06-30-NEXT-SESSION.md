# Honeypot project — handoff to the next Claude instance (2026-06-30)

**You are continuing a honeypot agentic-SOC portfolio project.** This doc is the current pointer. Read order:
1. **This file** (where we are + the immediate next action).
2. `infra/honeypot/HANDOFF.md` (🟢 0D-2 block) — canonical build state.
3. `infra/honeypot/ARCHITECTURE.md` — the plain-language walkthrough of the whole system (written this session).

> ⚠️ **User preference (important):** write in a **casual, conversational, slightly-technical tone** (like
> explaining to a sharp peer, not corporate). And **don't quiz them / don't over-ask** — lead with action and
> recommendations, only ask when a decision genuinely needs their input. They learn by doing. See the memory
> at `feedback_casual_conversational_tone`, `feedback_prefers_hands_on_doing`, `feedback_handson_instruction_format`.

---

## ▶ IMMEDIATE NEXT ACTION — finish sub-project C (one visual calibration)

We just added sticky-note documentation + section group-boxes to all 3 n8n workflow generators and regenerated
the JSON (commit `cd2c3ce`). Positions were placed **blind** (no canvas render), so the one open step is a
visual check:

- **The user imports `JSON/honeypot-triage.json` into n8n as a throwaway/scratch workflow** (NOT saving over or
  activating the live one) and screenshots the canvas.
- **You check:** do the 3 section boxes (① Ingest, Enrich & Ground / ② Triage (Opus) / ③ Verify & Route) sit
  cleanly *behind* their node clusters without overlapping, and does the top doc strip float above the nodes?
- **If off:** nudge the `sticky(...)` coordinates in `infra/honeypot/build_honeypot_triage_workflow.py` (the
  `nodes += [...]` block near the bottom), re-run `python infra/honeypot/build_honeypot_triage_workflow.py`,
  recommit. The poller + contain layouts are simple linear flows and follow the same recipe — spot-check if wanted.
- The throwaway import is just for looking. Getting the polished version onto the *live* workflow for the actual
  video is a separate footage-prep step (don't disturb the running workflows now).

Once that looks good, **C is done.**

---

## What this session did (2026-06-29 → 06-30)

### 1. Closed Phase 0D-2 ("Ship autonomous") — DONE
- **#10 bounded-watermark hardening** (`de814c8`): TDD'd `default_watermark` + bounded `load_state` in
  `grounding-service/grounding_service/falcon.py` (empty state → `now-24h` so the active poller can't silent-400).
  26 `test_falcon.py` tests green. **Deployed live** (md5-matched base64 sync over `az vm run-command`, rebuilt
  the `grounding-service` image; `/falcon/state` unchanged — no regression).
- **Synthetic real-IP "Contain recommended" demo** (`1502679`, `08bf78c`): path-validated deterministically.
  A crafted Falcon alert with a REAL AbuseIPDB-malicious IP (`2.57.121.25`, confidence 100) POSTed to the
  `honeypot-triage` webhook → full pipeline → **Iris #250** (HIGH) + Discord "⚠️ Contain recommended". Evidence in
  `infra/honeypot/falcon-0d2-validation.md` §6; reproducible body in `infra/honeypot/synthetic-demo-body.json` +
  runbook `synthetic-demo.md`. (An earlier incoherent attempt = Iris #249; the advisory judge correctly caught
  its `count:1` vs "sustained brute force" contradiction — a nice defense-in-depth anecdote. The clean body was
  designed via an adversarial vetting Workflow.)
- **Poller ACTIVATED** — `falcon-alert-poller` Schedule Trigger is **ON** (autonomous 15-min poll).
- Handoff updated (`3ad2212`): HANDOFF.md 🟢 0D-2 block + `0D-2-NEXT-SESSION.md`.

### 2. Pivoted to pre-Phase-1 portfolio prep — IN PROGRESS
The user wants to polish for going public + a video **before** starting Phase 1, inside the ~13-day Falcon trial
window. We decomposed into **4 deliverables**:

| # | Deliverable | Status |
|---|---|---|
| **A+B** | Project walkthrough + `ARCHITECTURE.md` (Mermaid: Layer-1 loop + Layer-2a–2d internals) | ✅ DONE (`e6022e8`) |
| **C** | Organize the 3 n8n workflows (sticky-note docs + section boxes, like the template gallery) | 🟡 generators+JSON DONE (`cd2c3ce`); **awaiting 1 calibration screenshot** (the next action above) |
| — | **Capture live Falcon demo footage** (contain round-trip + poller pull) | ⛔ PENDING — **trial-gated** |
| **D** | Organize the honeypot GitHub repo for **public** (secret-scrub, structure, README + embed the diagram) | ⛔ PENDING |

**Recommended sequence:** finish C → capture footage → D → (user records video) → then Phase 1.
**The only time-boxed thing is the Falcon footage** (everything else works post-trial) — schedule it before the
trial expires; raw-clip fallback by ~trial day 8.

### 3. Phase-bleed analysis (for scoping Phase 1/2 later)
Key finding from the spec (`docs/superpowers/specs/2026-06-22-honeypot-agentic-soc-design.md` §7): **Phases 1 & 2
are partly pre-built.** The RAG/Qdrant ATT&CK stack (Phase 2's core) is already live; the verifier gate +
advisory judge + eval/`runs.jsonl` (what Phase 1 red-teams + measures) all exist. So **Phase 1 (= roadmap C,
"adversarial red-team → before/after guardrail measurement") is "wire up + measure existing guardrails," not
"build guardrails."** Today's synthetic-injection + adversarial-vetting was a proto-Phase-1 motion. Honest debt:
the spec'd "bounded re-ground" was omitted from the live workflow (a miss → Needs-Human directly).

---

## Phase roadmap (from the spec — Phases 1-5 are roadmap-level only, NOT yet planned)
- **Phase 0** ✅ — honeypot → Splunk/Falcon → triage → verifier → Iris + Contain.
- **Phase 1** (= roadmap C) — Adversarial red-team, authentic. OWASP-LLM Top-10 / MITRE ATLAS payloads → before/after guardrail measurement. *"The differentiator."*
- **Phase 2** (= roadmap A) — RAG + detection-as-code (Qdrant corpus + Claude-drafted Sigma).
- **Phase 3** — Malware-triage add-on (hash→VT + Claude static de-obfuscation).
- **Phase 4** (= roadmap D) — splunk-MCP as a first-class Opus tool (component `splunk-mcp-main/` is staged).
- **Phase 5** (= roadmap E) — multi-agent (enrichment/triage/escalation + supervisor).

When the user is ready for Phase 1: **brainstorm it into its own spec → plan** (use the `superpowers:brainstorming`
then `writing-plans` flow). Don't start building Phase 1 without that.

---

## Live state the fresh instance MUST know (NOT in git)
- **Both SOC VMs are UP** — `vm-soc-v2-n8n` + `vm-soc-v2-splunk` (`rg-soc-v2-azure-central-us`). The user chose to
  **leave them up** for an organic-capture window; they auto-deallocate ~23:00 ET. ⚠️ **Deallocate when done:**
  `az vm deallocate -g rg-soc-v2-azure-central-us -n vm-soc-v2-n8n` (and `…-splunk`).
- **Falcon trial expires 2026-07-13** — anything needing the live Falcon API (poller real pulls, `falcon-contain`
  round-trip, demo footage) must happen before then. User said "operate as if 13 days" (extension is possible but
  don't count on it).
- **`falcon-alert-poller` is ACTIVE**; `grounding-service` runs the **#10** image; poller state watermark
  `2026-06-29T15:11:34.51Z`, `seen=[<EICAR>]` (untouched by the synthetic demo, which bypasses the poller).
- The synthetic demo used real malicious IP **`2.57.121.25`** (public threat-intel IOC — fine in committed evidence).

## Conventions (do not violate)
- **Never `git add -A`** — keep `Personal/`, `.playwright-mcp/`, `infra/honeypot/__pycache__/` out; add exact paths.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **No inline secret paste** — have the USER load secrets from the gitignored `Personal/honeypot-vm-creds.txt` /
  `SOC-Automation-Project.md`; secret-bearing commands run on a LOCAL machine, never the honeypot.
- **VM writes = base64 over `az vm run-command`** (n8n VM is Linux, `/root/soc-src` non-git) → **per-action USER
  approval**. `pytest` is dev-only (not in the prod image) → verify deploys via live route smoke, not in-container pytest.
- Hands-on blocks: lead with a **"Where:"** machine+access header, numbered commands, lists not prose.
- The honeypot webhook is a PRIVATE VNet IP (`http://10.0.0.6:5678/webhook/honeypot-triage`) — POST to it from
  inside the VNet (RDP to the Splunk VM, or `az vm run-command` curl on the n8n VM), not from a local machine.

## Git / push state
- Branch **`ai-upgrade`** in `SOC_Automation_Project`. Upstream = **`honeypot/ai-upgrade`**
  (`github.com/Armando-ic/soc-automation-honeypot-project`, single-branch repo — no base branch to PR against).
- This session's commits (`ai-upgrade`): `de814c8` `1502679` `08bf78c` `3ad2212` `e6022e8` `cd2c3ce` (+ this handoff).
  **Pushed to the honeypot remote** at end of session.
- Strategy/spec/plan docs live in the **parent workspace** `docs/superpowers/` which is **NOT a git repo** (not
  backed up to GitHub) — `ARCHITECTURE.md` and the in-repo evidence ARE committed.
