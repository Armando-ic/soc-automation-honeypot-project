# Honeypot Agentic-SOC — Master Project Checklist

**What this is:** the single living tracker for the whole honeypot project. It's for both of us. When we
finish something we check it off here, and when either of us needs to remember where we are, we read the
"Where we are right now" pointer and scan the phase we're in. Keep it current as work lands.

**Last updated:** 2026-07-01

**Companion docs (read these for detail, this file is the index):**
- Build state: [`HANDOFF.md`](HANDOFF.md) (canonical 🟢 0D-2 block)
- Plain-language walkthrough: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Latest session handoff: [`2026-06-30-NEXT-SESSION.md`](2026-06-30-NEXT-SESSION.md)
- Spec + plans live in the PARENT workspace `docs/superpowers/` (not a git repo)

**Status legend:** ✅ done · 🟡 in progress · ⬜ to do · ⛔ blocked / gated · ⏸️ deferred · ⏰ on a clock

---

## ▶ Where we are right now (2026-07-01)
Pre-Phase-1 portfolio prep. Phase 0 is fully shipped and the autonomous loop is live. Sub-projects **A, B, C,
and D are all done**, and the **repo is now PUBLIC** (flipped 2026-07-01; `ai-upgrade` is pushed and in sync
with `origin`). D landed the honeypot-forward README, the structure cleanup, a broader public-IP scrub, a scan
gate, and a multi-agent pre-publish audit that caught four secrets the regex scanners missed (a reused lab
password, the home IP, an Azure workspace GUID, and real CrowdStrike IDs, three of which were live-public on the
v1 `origin` repo). All four were redacted and history-purged from both repos with `git filter-repo`,
force-pushed, and verified clean. Today also landed the **five-diagram Mermaid visual-hierarchy pass**
(`4009320`) plus the **Layer-1 edge-readability follow-up** (`1411f72`). **No blocking manual items remain:**
the reused lab passwords are throwaway lab credentials and are intentionally **not** being rotated (user
decision 2026-07-01); the pending IRIS admin API key gets rotated when `vm-soc-v2-iris` is next allocated, not
before (it's offline now). **The next substantive work item is Phase 1** (adversarial red-team) — brainstorm to
spec to plan. The portfolio video and the live-Falcon footage are both deferred by decision (see those sections
below).

---

## ⏰ On a clock (time-sensitive, not deliverables)
- ⏰ **Falcon trial expires 2026-07-13** (12 days out as of 2026-07-01 — recompute against today). Anything
  that needs the live Falcon API (real poller pulls, contain round-trip, demo footage) has to happen before then.
- 🖥️ **All VMs currently deallocated** (verified 2026-07-01): `vm-soc-v2-n8n`, `vm-soc-v2-splunk`,
  `vm-soc-v2-iris`, `vm-soc-v2-win`, and `vm-honeypot-win`. No organic-capture window is open right now. Start
  the VMs you need before any live work; they auto-deallocate around 23:00 ET, so deallocate manually when done.
  (VM power state drifts fast — re-verify each session with `az vm list -d`.)

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
- ✅ Walkthrough written and `ARCHITECTURE.md` committed (`7350557`), with Mermaid diagrams for the
  Layer-1 loop and the Layer-2 internals.
- ✅ **Layer-1 + Layer-2 Mermaid visual-hierarchy pass (2026-07-01).** All five diagrams (Layer-1 in both the
  public README front door and `ARCHITECTURE.md`, plus the four Layer-2 internals: triage, verifier, poller,
  contain) restyled with one shared colour vocabulary (trust zones plus an AI-brain accent). Node labels
  stripped to role names with IPs/ports moved to edge labels and subgraph titles, external SaaS grouped into
  one box, `classDef` colours added, and each diagram pinned to Mermaid's dark theme via a `%%{init}%%` line so
  the subgraph titles stay readable on GitHub light **and** dark (a per-subgraph `style ... color:` is not
  reliably honoured by GitHub's Mermaid — known issue). Verified: the two Layer-1 copies are byte-identical, and
  a 6-agent fan-out confirmed node/edge fidelity against the generator code plus GitHub-render safety.
- ✅ **Layer-1 edge-readability follow-up (2026-07-01).** The `n8n` fan-out was hard to trace (many same-grey
  lines crossing to the External-services box). Fixed with `linkStyle`: the fan-out lines are coloured/thickened
  by role (contain red, case blue, enrich teal, notify pink, the Falcon poll feed lime) while the ingress lines
  are dimmed grey, plus `curve: basis`. Added a note under the diagram clarifying the colours are for visual
  clarity only, not a good/bad or risk rating.

### C. Organize the 3 n8n workflows for presentation ✅ DONE
- ✅ Sticky-note docs + section group-boxes added to all 3 workflow generators and JSON regenerated (`877c63d`).
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
- ✅ Commit C (generators + regenerated JSON + checklists) — landed across `73f9354`..`84cff8a`.

### Capture live Falcon footage ⛔ trial-gated (before 2026-07-13)
This is split from video production on purpose. The raw clips need live Falcon; the edit does not.
- ⬜ Contain round-trip clip (`falcon-contain`: normal → contained → normal).
- ⬜ Poller pull clip (the autonomous 15-min poll picking something up).
- ⬜ Optional showcase: the synthetic "Contain recommended" run end to end.
- ✅ **Decision (2026-06-30):** let the live-Falcon clips ride. The video is recorded only when the whole
  project is complete, and Falcon access gets re-established at that point rather than capturing insurance
  clips now.

### D. Organize the honeypot repo for public ✅ DONE (2026-07-01)
- ✅ Repo structure cleanup + honeypot-forward README with the ARCHITECTURE diagram (Tasks 1-6, `27c7cb7`..`5d30a95`).
- ✅ Broader public-IP `x.x.x.x` scrub (Task 6b, `3673980`) and the scan gate + gitleaks note (Task 7, `debe667`).
- ✅ **Multi-agent pre-publish audit + secret purge.** The semantic audit found four blockers gitleaks and
  trufflehog both rated clean: a reused lab password, the residential home IP, an Azure Log Analytics workspace
  GUID, and real CrowdStrike IDs in a test fixture. Redacted plus four approved PII scrubs applied in `2fd9013`,
  then history-purged from BOTH this repo and the public v1 `origin` via `git filter-repo` and force-pushed
  (`2fd9013` is the rewrite base; the branch has since advanced to `1411f72`). Verified zero occurrences across
  all commits. See the memory
  `secret-exposure-remediation-2026-07-01` and the plan `docs/superpowers/plans/2026-07-01-honeypot-repo-public-prep.md`.
- ✅ **Reviewed the rendered README and flipped the repo private → public (2026-07-01).**
- ✅ **Decision (2026-07-01):** the reused lab password is a throwaway lab credential and is intentionally
  **not** being rotated.
- ⏸️ **Deferred:** rotate the pending IRIS admin API key when `vm-soc-v2-iris` is next allocated (not before —
  it's offline now). Load the new value from the gitignored creds file, never inline.
- ✅ **Loose end resolved (2026-07-01):** `v4-gcp-native` was rebased `--onto` the clean `v3` base (`77c9952`) so
  it inherits no purged secrets, and backed up to the **PRIVATE** repo `Armando-ic/soc-v4-gcp-redacted`
  (gh-confirmed private). It **must stay private** (it documents the live redacted.com security design and
  blind spots) and would need a genericization pass before it could ever go public. See memory `soc-v4-gcp-redacted`.

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
- The public repo's default branch is intentionally `ai-upgrade` (deliberately not renamed to `main`).
