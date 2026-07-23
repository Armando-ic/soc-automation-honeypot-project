---
status: complete
updated: 2026-04-30
sub_project: A2
related: [[../2026-04-27-structured-outputs/README]], [[../../architecture/target-state]]
---

# Sub-project A2 — Iris Escalation Gate

If you are a fresh Claude Code instance picking this up, **read the files in this folder in this order**:

1. **This README** — context, scope, where things stand
2. **`spec.md`** — what we're building and why (created during brainstorming 2026-04-28)
3. **`plan.md`** — implementation steps (created by the writing-plans skill after spec approval)
4. **`runbook.md`** — how to operate the result (written during/after build)
5. **`notes.md`** — gotchas, learnings, open questions

Then check `../../log.md` for any entries dated after this README's `updated` field — they tell you what's happened since.

## Goal

Establish the **human-in-the-loop approval pattern** that all future response actions will reuse, with one minimal action behind the gate: alert→case escalation in DFIR-Iris with imported threat-intel IOCs.

The architectural deliverable is the gate pattern itself — Slack URL buttons → analyst's LAN browser → n8n Wait/Resume webhook → branch on `?decision=approve|deny`. Iris escalation is the test action because it's low-risk, semantically meaningful (it's the analyst's "this is real, work this" decision), and needs only one API call on Approve.

## In scope

- New: Slack approval message with URL buttons (Block Kit); n8n Wait/Resume webhook for the analyst's button click; escalate branch calling `/alerts/escalate/{alert_id}`; deny + timeout branches; outcome thread replies in Slack.
- Modify: A1's `Extract Triage Result` Code node — also produces `alert_iocs` payload (mapped from `iocs_enriched`, with hash-type detection and Iris IOC-type-ID lookup).
- Modify: A1's `Create Iris Alert` HTTP Request node — body now includes `alert_iocs`; response captured for `alert_id` and per-IOC UUIDs.
- Schema enhancement (additive): add `ioc_type` enum to each `iocs_enriched` item.
- Document: Iris IOC-type-ID catalog (one-time `/manage/ioc-types/list` lookup).
- A1 limitation fixed in passing: Iris description's markdown link → raw URL.
- Test: 5 pinned cases (gate-skipped, approve, deny, timeout, escalation-failure) + 1 e2e.

## Out of scope (deliberately)

- Splunk lookup blocklist (sub-project A3).
- Other action types (block IP, disable user, isolate host) — A3+.
- Public Slack interactivity / signed payloads — possible future "A2.5 — Tunnel + signed buttons" sub-project.
- Schema v2 / structured `proposed_actions` field — defer to A3 when a second action type makes the bump pay for itself.
- Webhook authentication on Splunk → n8n (still deferred, same as A1).

## Status

- [x] Brainstorm completed 2026-04-28
- [x] Spec written 2026-04-28
- [x] Spec approved 2026-04-28
- [x] [[plan|Implementation plan]] written 2026-04-28
- [x] Implementation executed (Phases 0-11, 2026-04-28 through 2026-04-29)
- [x] Runbook written (Phase 12, 2026-04-29)
- [x] Verification: 5 pinned tests (Phase 10) + e2e with real Splunk alert (Phase 11.2, runs against alerts #47/#48; Phase 12 follow-up against #50)

## Predecessors

- **A1 — Structured Outputs** (shipped 2026-04-28). Provides `iocs_enriched` array; A2's schema enhancement (`ioc_type`) is additive.

## Successors

Sequencing as of 2026-04-30 (see [[../../architecture/target-state#sequencing-decision-2026-04-30]] for rationale):

- **D1 — Detection foundations (Sysmon + Atomic Red Team + Splunk SPL practice).** Pulled ahead of A3; generates richer detection content the SOAR pipeline can consume. Job-prep priority drives the sequencing.
- **A3 — Splunk lookup blocklist.** Reuses A2's gate pattern with a second action type. Triggers schema bump to v2 per [[../../decisions/0005-additive-ioc-type-schema-enhancement]]. Architectural dependency on A2 is unchanged by the D1-first sequencing.
- **A2.5 — Tunnel + signed Slack interactivity** (optional, decoupled). Replace URL buttons with real Slack interactivity once a tunnel is set up.
- **B+ (EDR layer).** Generates richer alerts beyond what Sysmon covers (file-system collection, response actions, threat-intel integration); may absorb or extend D1.
