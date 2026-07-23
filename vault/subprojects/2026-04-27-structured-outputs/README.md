---
status: complete
updated: 2026-04-27
sub_project: A1
related: [[../../decisions/0003-split-structured-outputs-from-response-actions]]
---

# Sub-project A1 — Structured Outputs

If you are a fresh Claude Code instance picking this up, **read the files in this folder in this order**:

1. **This README** — context, scope, where things stand
2. **`spec.md`** — what we're building and why (created during brainstorming)
3. **`plan.md`** — implementation steps (created by the writing-plans skill after spec is approved)
4. **`runbook.md`** — how to operate the result (written during/after build)
5. **`notes.md`** — gotchas, learnings, open questions

Then check `../../log.md` for any entries dated after this README's `updated` field — they tell you what's happened since.

## Goal

Convert the current n8n triage workflow's freeform AI output into a structured JSON shape that downstream nodes consume reliably. Eliminate text parsing in favor of schema-driven field access.

## In scope

- Define the structured output schema (severity, IOCs, MITRE techniques, recommended actions, etc.)
- Refactor the Anthropic node to produce schema-conformant JSON
- Refactor downstream Slack and DFIR-Iris nodes to consume structured fields
- Fix three known bugs in the current workflow:
  - System prompt in `assistant` role → move to `system` role
  - Malformed `JSON.stringify(..., user, ComputerName, 2)` call → fix the replacer arg
  - AbuseIPDB API key inline → move to n8n credential
- Map AI-derived severity to DFIR-Iris `alert_severity_id` (no longer hardcoded `3`)
- Format the Slack message from structured fields (cleaner display, includes severity badge)

## Out of scope (deliberately)

- Response actions (sub-project A2)
- Webhook authentication (later phase)
- Detection improvements to the Splunk side (later phase)
- Adding a vector DB / case memory (Phase 3 work)

## Status

- [x] Brainstorm completed 2026-04-27
- [x] Spec written 2026-04-27
- [x] Spec approved 2026-04-27
- [x] Implementation plan written 2026-04-27
- [x] Implementation executed 2026-04-27 / 2026-04-28
- [x] Runbook written 2026-04-28
- [x] Verification: end-to-end with real Splunk alert succeeded; severity dynamic across 3 test cases (low → high → low-by-judgment); structured output observed in both DFIR-Iris and Slack

**A1 complete 2026-04-28.** See [[runbook]] for ongoing operations and [[notes]] for the full record of issues hit and decisions made along the way.

## Predecessors

None — this is the first sub-project after the original tutorial work.

## Successors

- [[../2026-04-28-iris-escalation-gate/README]] — **A2: Iris Escalation Gate** (active 2026-04-28). Reads A1's `iocs_enriched` field (filtered to malicious/suspicious) to drive a Slack-gated alert→case escalation in DFIR-Iris. Adds an additive schema field `ioc_type` to each `iocs_enriched` item; `severity` and `recommended_actions` remain unchanged (the latter is reserved for A3+).
