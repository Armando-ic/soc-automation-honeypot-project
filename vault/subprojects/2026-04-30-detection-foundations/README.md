---
status: complete
updated: 2026-04-30
sub_project: D1
related: [[../2026-04-28-iris-escalation-gate/README]], [[../../architecture/target-state]]
---

# Sub-project D1 — Detection Foundations

If you are a fresh Claude Code instance picking this up, **read the files in this folder in this order**:

1. **This README** — context, scope, where things stand
2. **`spec.md`** — what we're building and why (created during brainstorming 2026-04-30)
3. **`plan.md`** — implementation steps (created by the writing-plans skill after spec approval; not yet written)
4. **`runbook.md`** — how to operate the result (written during/after build; not yet written)
5. **`notes.md`** — gotchas, learnings, open questions (written during build; not yet written)

Then check `../../log.md` for any entries dated after this README's `updated` field — they tell you what's happened since.

## Goal

D1 stands up a **detection-engineering observation lab** on top of the existing SOC pipeline, with three layered deliverables:

**Primary** — the foundation. Sysmon installed on the Windows 10 VM with SwiftOnSecurity's off-the-shelf config; the existing Splunk Universal Forwarder carries the Sysmon channel into Splunk's `mydfir-project` index; Atomic Red Team installed so any MITRE technique can be invoked on demand. A documented routine + observation toolkit (EventCode reference + starter SPL queries + field reference) lets the user run any technique and trace it through Splunk.

**Secondary** — the integration test. One MITRE technique (T1059.001 PowerShell encoded command) is taken end-to-end through the existing SOAR pipeline as a working demonstration that A1's triage + A2's gate accept Sysmon-shaped alerts without n8n changes. Hand-written SPL → Splunk saved search → existing v2 webhook → existing pipeline. Gate-skipped path (Outcome A) expected; gated path (Outcome B) is acceptable variance.

**Tertiary** — the catalog seed. A new `vault/detections/` directory with a per-technique template and a coverage-index README. Future technique runs become a runbook routine, not a sub-project.

The **design driver** is job-prep — every D1 deliverable is something the user can point at in a SOC analyst interview and explain in 60–90 seconds.

## In scope

- Install Sysmon on the Windows 10 VM with SwiftOnSecurity's `sysmonconfig-export.xml` (off-the-shelf, no edits).
- Edit Universal Forwarder `inputs.conf` to capture the Sysmon channel; restart forwarder.
- Install Atomic Red Team via Red Canary's bootstrap script.
- Write the SPL detection for T1059.001 (regex flag-match + parent-process surfacing + stats aggregation), annotated inline.
- Create one Splunk saved search wrapping the SPL, posting to v2 production webhook URL on a 5-minute cron (`*/5 * * * *` — standard SOC cadence).
- Live-fire validation: `Invoke-AtomicTest T1059.001` traces end-to-end through the existing pipeline.
- Stand up `vault/detections/` directory + `_template.md` + `README.md` (coverage index) + `t1059-001-powershell-encoded.md` (worked example, populated).
- Update `vault/CLAUDE.md` to include `vault/detections/` in the schema table.
- Update `vault/architecture/components/splunk.md` with the new saved search and Sysmon sourcetype, cross-referenced to the new `sysmon.md`.
- Create `vault/architecture/components/sysmon.md` (new component page) with: what-it-is, where-it-runs, configuration table, EventCode reference table, field reference table, the "source= not sourcetype=" gotcha.
- Runbook covering: Sysmon install, Universal Forwarder edit, ART install, the run-a-technique loop, VMware Workstation snapshot discipline, 5–7 starter SPL queries (annotated), security-posture note (Defender off, intentional). Reference catalogs (EventCode + field tables) live in `sysmon.md` and are referenced, not duplicated.
- Log entry at vault root marks D1 complete.

## Out of scope (deliberately)

- Pre-writing SPL or saved searches for techniques the user hasn't run.
- Sysmon config tuning (no edits to SwiftOnSecurity's XML in D1).
- AI base64-decoding of the encoded PowerShell payload (defers as "D1.5" extension).
- System prompt addendum for Sysmon-shaped alerts (reactive only — runbook documents standby fix).
- Sigma rule format (sub-project C).
- Automated/scheduled ART runs (sub-project H).
- EDR layer (sub-project B).
- Multi-endpoint Sysmon deployment.
- Splunk free-tier license replacement.
- Re-litigating the Defender-off lab posture.

## Status

- [x] Brainstorm completed 2026-04-30
- [x] Spec written 2026-04-30
- [x] Spec approved 2026-04-30 (with in-flight Errata E1-E6 capturing realities Phase 0 surfaced)
- [x] Implementation plan written 2026-04-30
- [x] Implementation executed 2026-04-30 (Phases 1-9; live-fire PASS, Outcome A confirmed)
- [x] Runbook written 2026-04-30
- [x] Log entry closing D1

## Predecessors

- **A1 — Structured Outputs** (shipped 2026-04-28). Provides the schema-driven Claude triage that D1's worked-example saved search exercises.
- **A2 — Iris Escalation Gate** (shipped 2026-04-30). Provides the human-in-the-loop gate. D1's worked-example fires the gate-skipped path (matching A2 Test 1) on Sysmon-shaped data.

## Successors

Sequencing as of 2026-04-30 (per [[../../architecture/target-state#sequencing-decision-2026-04-30]]):

- **A3 — Splunk lookup blocklist.** Architectural dependency on A2's gate pattern unchanged by D1.
- **C — Detection engineering at scale.** Inherits D1's `vault/detections/` directory + per-technique-page pattern.
- **H — Automated purple team.** Inherits D1's manual run loop as the basis for cron-driven automation.
- **B — EDR layer.** Independent; can extend or replace D1's Sysmon-only telemetry surface.
