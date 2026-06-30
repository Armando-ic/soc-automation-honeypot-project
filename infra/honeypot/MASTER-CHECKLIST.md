# Honeypot Agentic-SOC — Master Project Checklist

**What this is:** the single living tracker for the whole honeypot project. It's for both of us. When we
finish something we check it off here, and when either of us needs to remember where we are, we read the
"Where we are right now" pointer and scan the phase we're in. Keep it current as work lands.

**Last updated:** 2026-06-30

**Companion docs (read these for detail, this file is the index):**
- Build state: [`HANDOFF.md`](HANDOFF.md) (canonical 🟢 0D-2 block)
- Plain-language walkthrough: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Latest session handoff: [`2026-06-30-NEXT-SESSION.md`](2026-06-30-NEXT-SESSION.md)
- Spec + plans live in the PARENT workspace `docs/superpowers/` (not a git repo)

**Status legend:** ✅ done · 🟡 in progress · ⬜ to do · ⛔ blocked / gated · ⏸️ deferred · ⏰ on a clock

---

## ▶ Where we are right now (2026-06-30)
Pre-Phase-1 portfolio prep. Phase 0 is fully shipped and the autonomous loop is live. Sub-projects **A, B,
and C are all done** now: the three n8n workflows are organized for presentation (doc strips, section
group-boxes, voice-passed cards) and committed (`84453f2`). The next deliverable is sub-project **D**:
organize the honeypot repo for public (secret-scrub pass, repo structure cleanup, a public README with the
ARCHITECTURE diagram embedded). The portfolio video and the live-Falcon footage are both deferred by
decision (see those sections below).

---

## ⏰ On a clock (time-sensitive, not deliverables)
- ⏰ **Falcon trial expires 2026-07-13** (treat it as ~13 days). Anything that needs the live Falcon API
  (real poller pulls, contain round-trip, demo footage) has to happen before then.
- 🖥️ **Both SOC VMs are up** (`vm-soc-v2-n8n`, `vm-soc-v2-splunk`) for an organic-capture window. They
  auto-deallocate around 23:00 ET. Deallocate manually when we're done for the day.

---

## Phase 0 — Foundation ✅ DONE
Internet-exposed Windows honeypot → Splunk / Falcon → n8n SOAR → Claude Opus triage (verifier-gated) →
DFIR-Iris + Discord, with CrowdStrike Falcon as detect-only EDR plus Contain.

- ✅ **0A — Azure infra + telemetry.** Honeypot VM, Sysmon, Universal Forwarder → Splunk `honeypot` index, e2e validated.
- ✅ **0B — Falcon.** Detect-only sensor + OAuth API + Contain → Lift all validated (`normal → contained → normal`).
- ✅ **0C — Pipeline software (TDD).** `grounding-service` with `/normalize`, `/retrieve`, `/verify`.
- ✅ **0D-1 — n8n wiring.** `honeypot-triage` workflow built and live-triggered (the loop runs end to end).
- ✅ **0D-2 — Falcon poll trigger + Contain.** Poller is ACTIVE (15-min autonomous poll), #10 watermark
  hardening deployed, synthetic "Contain recommended" demo path-validated (Iris #250), human-fired
  `falcon-contain` round-trip validated.
  - ⏸️ **Watchdog (auto-lift) deferred** (the timed auto-lift after a contain).
- 📝 **Known debt (input to Phase 1):** the spec'd "bounded re-ground" was left out of the live workflow,
  so a verifier FAIL routes straight to Needs-Human instead of trying one grounded retry first.
- 📝 **Known debt (low-pri polish):** the `Has IOC` gate in `honeypot-triage` routes on whether `src_ip` is
  non-empty, not on the private-excluding `enrich_ips`, so a private-but-non-empty source IP would still be
  sent to AbuseIPDB/GreyNoise (the parser's `isPrivate()` logic only affects which IPs get listed as IOCs).
  Harmless for a honeypot since attacker IPs are effectively always external. Found by the 2026-06-30
  doc-accuracy verification pass.

---

## Pre-Phase-1 — Portfolio Prep 🟡 CURRENT

### A + B. Project walkthrough + ARCHITECTURE.md ✅ DONE
- ✅ Walkthrough written and `ARCHITECTURE.md` committed (`e6022e8`), with Mermaid diagrams for the
  Layer-1 loop and the Layer-2 internals.

### C. Organize the 3 n8n workflows for presentation ✅ DONE
- ✅ Sticky-note docs + section group-boxes added to all 3 workflow generators and JSON regenerated (`cd2c3ce`).
- ✅ Visual calibration of the `honeypot-triage` canvas (you hand-tuned positions and colors; every node
  verified sitting cleanly inside its section box).
- ✅ `honeypot-triage` "What it does" card rewritten in the preferred voice (wording locked).
- ✅ **Folded the layout, colors, and card text back into `build_honeypot_triage_workflow.py`** (2026-06-30)
  via an authoritative `POS` map, regenerating the clean public-ready JSON (7 `REPLACE_ME` placeholders, no
  `instanceId`/`versionId`, name back to `honeypot-triage`). User then re-laid the doc strip (How It Works
  widened to 1004x232, Notes/Customization/Setup stacked) and screenshot-confirmed it fits.
- ✅ **Voice pass on the other 6 cards** (① Ingest, ② Triage, ③ Verify, Notes, Customization, Setup) rewritten
  to the casual full-sentence convention, no em dashes, no arrow shorthand.
- ✅ **Doc-accuracy verification** (5-agent Workflow fact-checking every card claim against the code): fixed
  "Iris case" → "Iris alert" (the nodes create alerts), the Notes IOC-gate wording (skips only when there's no
  source IP), and card ② (Opus is *instructed* to stay grounded; the verifier *enforces* it). Two overview
  imprecisions left as acceptable summary simplifications (user's call).
- ✅ **Poller + contain workflows** (2026-06-30): user re-laid both canvases and exported; folded their layouts
  back into the generators (POS maps; sections recolored near-black; the poller `IF has_new` node, accidentally
  deleted in the export, was re-added at [940,0]). Voice pass on all cards plus a 12-agent doc-accuracy fan-out
  tightened several imprecisions (poller "identical" → "same pipeline", "exactly once" → bounded "once", restored
  the per-run cap, "ack for every one" → "until the first failure"; contain "verifies" → "reads back the status",
  "never strands" → "always attempts a self-lift", the contained-status read reframed as observed-not-gated). No
  hard bugs found.
- ✅ Commit C (generators + regenerated JSON + checklists) — landed as `84453f2`.

### Capture live Falcon footage ⛔ trial-gated (before 2026-07-13)
This is split from video production on purpose. The raw clips need live Falcon; the edit does not.
- ⬜ Contain round-trip clip (`falcon-contain`: normal → contained → normal).
- ⬜ Poller pull clip (the autonomous 15-min poll picking something up).
- ⬜ Optional showcase: the synthetic "Contain recommended" run end to end.
- ✅ **Decision (2026-06-30):** let the live-Falcon clips ride. The video is recorded only when the whole
  project is complete, and Falcon access gets re-established at that point rather than capturing insurance
  clips now.

### D. Organize the honeypot repo for public ⬜
- ⬜ Secret-scrub pass (gitignored creds file, any baked credential IDs / `instanceId`, the plaintext
  secrets in `SOC-Automation-Project.md`).
- ⬜ Repo structure cleanup.
- ⬜ Public README with the ARCHITECTURE diagram embedded.

---

## Phases 1–5 — Roadmap ⬜ (not yet planned)
Each phase gets brainstormed into its own spec then plan before any building starts.

- ⬜ **Phase 1 — Adversarial red-team (the differentiator).** OWASP-LLM Top-10 / MITRE ATLAS payloads
  against the guardrails, with before/after measurement. Note: much of the scaffolding (verifier gate,
  advisory judge, eval harness) already exists, so this is "wire up + measure," not "build from scratch."
- ⬜ **Phase 2 — RAG + detection-as-code.** Qdrant corpus already live; add Claude-drafted Sigma rules.
- ⬜ **Phase 3 — Malware-triage add-on.** hash → VirusTotal + Claude static de-obfuscation.
- ⬜ **Phase 4 — splunk-MCP as a first-class Opus tool** (`splunk-mcp-main/` is staged).
- ⬜ **Phase 5 — Multi-agent.** Enrichment / triage / escalation agents plus a supervisor.

---

## After all main phases ⏸️ DEFERRED (by decision, 2026-06-30)
- ⏸️ **Record + produce the portfolio video.** Deferred until the full system (Phases 1–5) is built, so the
  walkthrough shows the finished thing. See the trial-clock note above for the live-Falcon footage caveat.
- ⏸️ **A3 — Enrichment expansion** (urlscan.io, URLhaus, IP2Location). Likely dropped permanently if the
  later phases deliver more portfolio value; revisit only if it still makes sense.

---

## Conventions reminder (full list in the handoffs)
- Never `git add -A`; add exact paths. Keep `Personal/`, `.playwright-mcp/`, `__pycache__/` out.
- No inline secret paste; the user loads secrets from the gitignored creds file on a local machine.
- VM writes go via base64 over `az vm run-command` with per-action approval.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
