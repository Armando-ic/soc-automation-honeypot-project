# Honeypot Agentic-SOC — Master Project Checklist

**What this is:** the **phase index** for the whole honeypot project — the deliverable checklist across
Phases 0-5. It's for both of us. When we finish something we check it off here. For "where are we right
now", read [`CURRENT-STATE.md`](CURRENT-STATE.md) instead; this file holds the durable phase record and
should change slowly. Keep it current as work lands.

**Last updated:** 2026-08-10

**Companion docs (read these for detail, this file is the index):**
- ▶ **Live state: [`CURRENT-STATE.md`](CURRENT-STATE.md)** — the situational snapshot, start here each session
- ▶ **Active experiment: [`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md)** — Tier-1 plan + ⬜ execution tracker
- Build state: [`HANDOFF.md`](HANDOFF.md) (canonical 🟢 0D-2 block)
- Plain-language walkthrough: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Latest session handoff: [`2026-08-08-SESSION47-FIRST-INTRUSION-CAPTURED-DOCUMENTED-TIER1-NEXT-HANDOFF.md`](2026-08-08-SESSION47-FIRST-INTRUSION-CAPTURED-DOCUMENTED-TIER1-NEXT-HANDOFF.md) (honeypot: **the box was broken into**, incident documented, Tier-1 concealment queued) · [`2026-07-22-DOC-LINT-SHIPPED-TRIAGE-B1-DONE-HANDOFF.md`](2026-07-22-DOC-LINT-SHIPPED-TRIAGE-B1-DONE-HANDOFF.md) (/lint track)
- Next-instance kickoff prompts (two independent tracks): [`2026-07-22-DOC-LINT-TRIAGE-CONTINUE-KICKOFF-PROMPT.md`](2026-07-22-DOC-LINT-TRIAGE-CONTINUE-KICKOFF-PROMPT.md) (`/lint` SHIPPED public + 2 triage buckets done; 2 buckets remain) · [`2026-08-08-SESSION48-HANDOFF-PROMPT.md`](2026-08-08-SESSION48-HANDOFF-PROMPT.md) (honeypot live op: Tier-1 concealment, then resume the watch)
- Live-op runbooks (hands-on, copy-paste): [`honeypot-opening-runbook.md`](../honeypot-opening-runbook.md) (re-arm → open → monitor) + [`b9-teardown-runbook.md`](../b9-teardown-runbook.md) (teardown)
- Spec + plans live in the PARENT workspace `docs/superpowers/` (not a git repo)

**Status legend:** ✅ done · 🟡 in progress · ⬜ to do · ⛔ blocked / gated · ⏸️ deferred · ⏰ on a clock

---

## ▶ Where we are right now

**Live state moved out of this file 2026-08-10.** It changed every session and churned the phase index
underneath it. Two dedicated files now own it:

| Read this | For |
|---|---|
| **[`CURRENT-STATE.md`](CURRENT-STATE.md)** | **The situational snapshot — start here.** What just happened, what's live, what's residual |
| **[`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md)** | The **active experiment** — Tier-1 plan, ripple-check evidence, and the ⬜ execution tracker |

**One-line status (2026-08-10):** 🔴 **the box was broken into** on 2026-08-08 (Logon Type 10 from
`113.203.61.61`, 54 seconds, **zero impact**) — see
[`INC-2026-001`](../incidents/INC-2026-001-first-interactive-intrusion.md), now **public** at tip
`fd039a7`. ▶ **Next move: Tier-1 concealment, execution in progress.** B9 teardown deliberately undecided.

**This file is the phase index** — the deliverable checklist across Phases 0-5. Per-session narrative and
every live-measured fact live in `session-logs/` (dated handoffs) + `.superpowers/sdd/progress.md` (SDD
ledger); read the latest handoff for "what happened last."

---

## ⏰ On a clock (time-sensitive, not deliverables)
- ☠️ **Falcon trial EXPIRED 2026-07-28.** The clock ran out; a 2nd extension had been refused in writing.
  **The auto-brake was NOT affected** — verified in `build_honeypot_brake_workflow.py`: `nsg_deny` fires
  before Falcon is attempted, the Discord alert hangs off `nsg_deny` rather than the Falcon chain, and every
  Falcon node is non-halting (the A10 rework of 2026-07-15 was built for this date). **No code change was
  needed.** Sign-off 2 was re-signed without Falcon on 2026-07-30.
  - ✅ **`falcon-alert-poller` DISABLED in n8n 2026-07-30** (unpublished + inactive). It was 401ing every
    15 min against the dead trial. Deactivated rather than deleted — the workflow is still a legitimate
    portfolio artifact and the generator (`build_falcon_poller_workflow.py`) stays in the repo.
  - ✅ Runbook no-ops landed 2026-07-30: opening-runbook **A4** retired, **C2** Falcon embed line marked
    cosmetic, **C5** revert is now the NSG delete alone. There was never a Falcon step in the B9 runbook
    (the session-45 handoff claimed one; checked firsthand, it does not exist).
  - ✅ **Public-repo honesty pass DONE** (landed 2026-07-30, checkbox corrected 2026-08-10 after verifying
    firsthand — it had been sitting `⬜` while already complete). The dated "validated against a trial that
    ended 2026-07-28 / the brake is deliberately EDR-independent" note is present in root
    [`README.md`](../../../README.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md) and
    [`infra/honeypot/README.md`](../README.md). The integration stays documented — the independence is the
    better story.
  - Also gone: the human-fired `falcon-contain`, the fast-contain layer, the EDR detections feed, and the
    3 never-captured live-Falcon clips.
- 🖥️ **VM power — the standing posture is now RUNNING, not parked** (Decision 1 superseded 2026-07-30).
  `vm-honeypot-win`, `vm-soc-v2-splunk` and `vm-soc-v2-n8n` are meant to stay up between sessions; `vm-soc-v2-iris` /
  `vm-soc-v2-win` are not part of the live op. **Never infer power state — re-verify every session with
  `az vm list -d -o table`,** and if the honeypot came back up, Decision 2's interlock applies (re-run Phase A+B+C,
  honeypot started LAST).
  - ⬜ **BLOCKS Decision 1's supersession — the SOC boxes auto-shut down and they carry the brake.** Checked
    2026-07-30: `vm-honeypot-win` has **no** schedule (good), but `shutdown-computevm-vm-soc-v2-splunk` and
    `shutdown-computevm-vm-soc-v2-n8n` **do**. The auto-brake does not live on the honeypot — its only built
    feeder runs an SPL search against Splunk every minute and posts to n8n, so **Splunk down = brake blind,
    n8n down = brake dead + no Discord alert.** Left as-is, the honeypot sits open all night with only the
    static NSG envelope, which is worse than the old Decision 1. Disable both with
    `az vm auto-shutdown -g rg-soc-v2-azure-central-us -n <vm> --off`; leave `iris` / `win` alone.
  - 💸 **`VM stopped` ≠ `VM deallocated`.** An in-guest Windows shutdown leaves Azure billing compute. Park
    the box with `az vm deallocate` or you pay for a VM that is doing nothing (observed 2026-07-27 → 07-30).

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

## Pre-Phase-1 — Portfolio Prep ✅ DONE (2026-07-01; live-Falcon footage + portfolio video deferred by decision)

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
  it inherits no purged secrets, and was backed up to a **separate private repository** (gh-confirmed private).
  It **must stay private** and would need a genericization pass before it could ever go public. See the
  private-project note in local memory.

---

## Phases 1-5 - Roadmap (Phases 1-4 ✅ COMPLETE + PUBLISHED; Phase 5 ▶ NEXT, brainstorm-first)
Each phase gets brainstormed into its own spec then plan before any building starts.

- ✅ **Phase 1 — Adversarial red-team (the differentiator). COMPLETE + PUBLISHED** (Plan 1 harness+baseline and Plan 2
  hardening both shipped to public `origin/ai-upgrade`). OWASP-LLM Top-10 / MITRE ATLAS payloads
  against the guardrails, with before/after measurement. Note: much of the scaffolding (verifier gate,
  advisory judge, eval harness) already exists, so this is "wire up + measure," not "build from scratch."
  - ✅ **Brainstormed → spec v2.1 → plan v2.1** (PARENT `docs/superpowers/`, non-git):
    `specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` +
    `plans/2026-07-01-honeypot-phase1-redteam-harness-baseline.md`.
  - ✅ **Snapshot-independent half of the harness BUILT + reviewed + green (2026-07-02).** Package `red-team/`:
    scaffold, `system_prompt`, `model_client`, `retriever`, `cases`, `scorer`, `stats`, and the 12-case A1–E1
    seed corpus. Local commits `b6b263e..4d7811f` on `ai-upgrade` (15 ahead of public, NOT pushed), 65/65 tests
    pristine, 12-agent adversarial final review + fixes done. Ledger: `.superpowers/sdd/progress.md`.
  - ✅ **Task 2 (n8n snapshot capture) DONE (2026-07-02, commit `b266570`).** Splunk run 275 + Falcon run 281
    captured from n8n history into `red-team/snapshots/`, six load-bearing fields each, link-drift reconciled to
    committed behavior, SOC infra IPs stripped, attacker IPs kept public (user decision). VM can deallocate.
  - ✅ **T4/5/6 JS→Python ports DONE (2026-07-02).** `parse_alert` + `build_opus_input` + case body-builders
    (`input_builder.py`) + `extract_result.py`, all TDD byte-fidelity vs the snapshots, each SDD-reviewed clean
    (Task 6 took one fix round: graceful `.get()` on malformed IOC fields). Full red-team suite **85/85**. Commits
    `5513e9b`, `71b9b67`, `7cac133`..`0f86daf` on `ai-upgrade` (local).
  - ✅ **T12 runner + T13 report + T14b held-out corpus DONE (2026-07-02).** `runner.py` (`run_case` K-loop),
    `report.py` (`build_baseline_report`, Clopper-Pearson CIs, OPEN labels), and 13 blind-authored held-out cases.
    Commits `74bba21`(T12) `d3a3953`(T13) `3930e71`+`6b1ffc3`(T14b) on `ai-upgrade` (local).
  - ✅ **Final whole-branch adversarial review + 2-wave fix DONE (2026-07-03).** 23-agent Workflow found 2 Crit +
    6 Imp + 7 Min (all survived verify); fixed across `eb03b94`..`6302626` + independent re-review "Ready to merge".
    Net: crash-safety on adversarial model output, 5 raw-buried seed payloads relocated + a per-source loader
    contract guard, D1 reclassified as a structural pipeline-integrity test, corpus now measures **7 model-attack
    classes {A1,A2,A3,A4,B1,C1,E1}** / 10 predicates / seed 10 + held-out 11.
  - ✅ **T15 offline half DONE (2026-07-03).** `red-team/scripts/run_baseline.py` — thin DI CLI (`--k`,
    `--headline CLASS:K`, `--attacks`, `--out`, `--dry-run`, `--concurrency N` with streamed live progress) over the
    frozen harness; 3 SDD tasks (impl + independent review each), full suite **134/134**. Commits `ddedfe5`, `3ba83d2`,
    `9825141` on `ai-upgrade` (local; 34 ahead of public, NOT pushed).
  - ✅ **T15 live run = Gate-3 DONE (2026-07-04).** Headline pass ran clean: **455 live `claude-opus-4-8` calls,
    0 errors / 0 invalid / 0 refusal / 0 truncation**. Committed `reports/baseline-9825141.md` (HEAD `b395e39`,
    35 ahead of public, NOT pushed). **3 confirmed unmitigated bypasses = Plan-2 targets: A1 count-string 50/50
    (100%), A3 hot-tactic 46/50 (92%), C1 exfil 17/50 (34%)**; E1 IOC-normalization gate held (45 emitted, 0
    passed); A2/B1 (OPEN) + A4 clean upper-bound rows. Report is faithful (Clopper-Pearson CIs, zero as upper
    bounds, INVALID/outcome separate, header carries model + MAX_TOKENS 4096 + commit). Nuance for the writeup:
    the mechanical OPEN label flags 5 classes {A1,A2,B1,C1,E1} (deviated==bypassed there by construction), and
    E1's OPEN boilerplate reads inverted (its 0% is a real gate catch) — footnote, don't fix the frozen report.py.
  - ✅ **PLAN 1 COMPLETE + PUBLISHED (2026-07-04, session 13).** `finishing-a-development-branch` done: a pre-push
    secret/IP scrub (mechanical + a 6-lens semantic audit Workflow) then a `git filter-repo` history rewrite that
    purged 6 real IOCs (recoverable only from intermediate-commit history) and the already-public `lolasparty.com`
    disclosure, force-pushed to the public remote (`b6b263e...8d61f42`, 136 commits rewritten). Verified 0 residual
    across all 249 commits; published tip byte-identical except the neutralized checklist doc lines (red-team/
    unchanged → 134/134). Main repo reconciled + in sync. The old stray `7MV` Anthropic key was located + revoked.
  - ✅ **PLAN 2 (hardening) COMPLETE + PUBLISHED (sessions 15-16, 2026-07-05; public tip `a4f8e28`, repo 0/0).**
    Brainstormed → spec → `writing-plans` → gate-2 red-team → subagent-driven build (Tasks 1-5, each
    per-task reviewed) → 11-agent whole-branch review (READY TO MERGE, 2 Minors) → an **A3 parent roll-up** added when
    the live probe showed hot parents absent from the retrieved pool (grounding-service retriever rolls retrieved subs
    up to the parent's real payload; commit `c161b97`) → the **paid after-run** (275 live `claude-opus-4-8` calls, 0
    invalid) → **C1 residual capture** (K=15) confirming the gate. Modified the PRODUCTION pipeline only
    (grounding-service rerank+roll-up / triage-verifier notes-leak gate / deployed prompt); the frozen + public
    red-team harness was untouched and re-ran to measure. Spec + Plans in PARENT `docs/superpowers/` (non-git):
    `specs/2026-07-04-honeypot-phase1-plan2-hardening-design.md` + `plans/2026-07-04-honeypot-phase1-plan2-hardening.md`
    + `plans/2026-07-05-honeypot-a3-parent-rollup.md`.
    - ✅ **RESULT (honest before/after): A1 100%→0% GENUINELY CLOSED, A3 92%→0% GENUINELY CLOSED, C1 34%→62% = a
      frozen-scorer MEASUREMENT ARTIFACT** (the production notes gate is proven correct offline + live: 0 real dumps
      slipped, 0 disagreements; the frozen scorer's ≥1-token tripwire over-counts benign `mitre_techniques` mentions
      in refusal notes). After-report committed `7a46f25` + a public-facing C1 companion note `a4f8e28`. Do NOT lower
      the gate bar to chase the C1 number. Full writeup: SDD ledger `.superpowers/sdd/progress.md` SESSION 16 block.
    - ✅ **STEP 5 DONE + PUBLISHED (2026-07-05, session 16).** `finishing-a-development-branch`: USER chose scrub+push
      and yes to the companion note. Fresh pre-push scrub CLEAN at both layers — mechanical (gitleaks 0 / trufflehog 0
      / targeted greps: only IP 203.0.113.10 RFC5737, no lab identifiers) + a 6-lens semantic audit Workflow (0
      findings, verdict CLEAN, run wf_1e777558-e6b). Clean fast-forward `git push origin ai-upgrade` (`8d61f42..a4f8e28`,
      no force). **Public tip is now `a4f8e28`, repo 0/0 in sync. Plan 2 hardening is PUBLIC.**
- ✅ **Phase 2 — RAG + detection-as-code. BUILD COMPLETE + LIVE-RUN DONE (2026-07-07).** The `detection-authoring`
  package (compile/pySigma, frozen corpus, 4-tier gate, RAG grounding, Claude drafter, stats+report, catalog, DI CLI,
  Zircolite cross-check) is built; offline suite **54/54**. Task 15 paid live run landed the evidence: **T1059.001 5/5
  gate-passed, T1059.003 0/5** (honest FP-quiet-tier finding). A live list-of-maps subset-boundary finding was fixed
  test-first via a drafter prompt steer (`cab1e37`). HEAD `a7b2039`, 28 ahead of public (unpushed). Deferred: Zircolite
  cross-check, pre-publish items, scrub gate + push. See the SESSION 20 block at the top.
- ✅ **Phase 3 — Malware de-obfuscation triage. BUILD COMPLETE + LIVE-RUN DONE + PUBLISHED (2026-07-11).** The
  `malware-triage` package (deterministic Class-A builtin decoders, a byte-exact ground-truth gate where Claude only
  *proposes* transforms and the gate re-executes + verifies-or-rejects, versioned behavioral rules, IOC extraction + VT
  verdict fusion, a 5-section report) + the grounding-service `/deobfuscate` + `/triage-verdict` endpoints + the n8n
  de-obfuscation branch. 16-task plan via subagent-driven-development with adversarial audit Workflows at every checkpoint.
  Suites: malware-triage **105** / builder **14** / grounding-service **88** (+2 known reds). **Task 16 paid live run:**
  corpus 5/6 verdict==label on the first run (the 6th, a mixed plaintext+ROT13 corpus bug, relabeled `unknown` +
  regression-locked — the byte-exact gate correctly refused a real model's non-byte-exact decode); 3 real captured
  `-EncodedCommand` from Splunk `index=mydfir-project` all builtin-decoded and `clean` (self-authored T1059.001
  validation; `index=honeypot` = brute-force only); two-layer scrub gate CLEAN. Fast-forward push `0f897ea..6fd2493`
  (42 commits, no force). **Public tip `6fd2493`, repo 0/0. PHASE 3 IS PUBLIC.** See the SESSION 28 block at the top.
- ✅ **Phase 4 - Splunk investigation agent (grounded, entity-scoped triage). COMPLETE + PUBLISHED (2026-07-13, `d7a1bf3`).**
  A bounded Opus tool-loop over a parameterized entity-bound Splunk query catalog emits FLAT `scope_evidence` that a
  `scope_grounded` verifier family checks OUT of model control (fails closed). Live run: a real honeypot brute-force
  scoped end-to-end, grounded + rows-free; found + fixed test-first a verifier deploy bug (image missing
  `JSON/honeypot-triage.json`); live severity ablation NOT-MET (grounding proof = offline synthetic demo); triage
  over-escalation surfaced honestly. Vault: `subprojects/2026-07-13-splunk-investigation-agent/`. See the Session 36 block at the top.
- ▶ **Phase 5 - Multi-agent supervisor. NEXT (brainstorm-first; NO spec/plan/code yet).** Enrichment / triage /
  escalation agents plus a supervisor over the existing grounding-service pipeline. Open the brainstorm with
  `superpowers:brainstorming`: what does a supervisor add over the deterministic n8n graph, and how does it preserve
  the load-bearing grounded / fails-closed / out-of-model-control invariant every prior phase kept? Companion
  honeypot-opening spec is un-blocked (Falcon trial extended to 2026-07-28) and could interleave if the USER pivots.

---

## After all main phases ⏸️ DEFERRED (by decision, 2026-06-30)
- ⏸️ **Record + produce the portfolio video.** Deferred until the full system (Phases 1–5) is built, so the
  walkthrough shows the finished thing. See the trial-clock note above for the live-Falcon footage caveat.
- ⏸️ **A3 — Enrichment expansion** (urlscan.io, URLhaus, IP2Location). Likely dropped permanently if the
  later phases deliver more portfolio value; revisit only if it still makes sense.

---

## 🛠️ Tooling
- ✅ **`/lint` doc-consistency linter** — BUILT 2026-07-21, **SHIPPED PUBLIC 2026-07-22**. `tools/doc_lint.py` (Tier 1, stdlib-only, 18/18 tests) + `.claude/commands/lint.md` (Tier-1+2 orchestrator) + `lint-log.md` journal. `.claude/*`+`!.claude/commands/` gitignore negation applied so the command is first-class tracked. First full `/lint` run: **42 Tier-1** + (**9 real contradictions / 38 real stale**) Tier-2. Triage done + pushed: **high-value-core** (`7696f27` — 12 component wiki-link depth-fixes + Falcon date 07-13→07-28) + **vault-currency** (`a6ddef5` — `claude-api`/`current-state`/`target-state`/`starting-the-vms`); `doc_lint` now **42→27**. Public tip `a6ddef5`. **2 buckets remain** (Tier-1 remainder + a linter per-dir-frontmatter-keys code change) — see [`2026-07-22-DOC-LINT-SHIPPED-TRIAGE-B1-DONE-HANDOFF.md`](2026-07-22-DOC-LINT-SHIPPED-TRIAGE-B1-DONE-HANDOFF.md). NOT the scrub gate, NOT black/isort/mypy.

---

## Conventions reminder (full list in the handoffs)
- Never `git add -A`; add exact paths. Keep `Personal/`, `.playwright-mcp/`, `__pycache__/` out.
- No inline secret paste; the user loads secrets from the gitignored creds file on a local machine.
- VM writes go via base64 over `az vm run-command` with per-action approval.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- The public repo's default branch is intentionally `ai-upgrade` (deliberately not renamed to `main`).
