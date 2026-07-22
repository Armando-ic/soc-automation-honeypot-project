---
status: superseded
updated: 2026-07-22
related: [[architecture/current-state]]
---

# Target State

> **Superseded (2026-07-22).** This is the original v1 SOC_Automation_Project roadmap, frozen at 2026-04-30. Development moved to the **honeypot agentic-SOC upgrade** (Phases 0-4 shipped + public; see [`infra/honeypot/`](../../infra/honeypot/)), which realized parts of this direction under different framing — D1 detection foundations, RAG case-memory (E/F below), and multi-agent triage. Kept as a historical record of the original plan.

Where the project is heading. Not a commitment — a direction. Updated as sub-projects ship and priorities evolve.

## Phase 1 — Tighten the foundation

- [x] **A1: Structured Outputs** — schema-driven AI responses, fix the known bugs ([[subprojects/2026-04-27-structured-outputs/README]]) — shipped 2026-04-28
- [x] **A2: Iris Escalation Gate** — human-in-the-loop Slack URL-button approval gate; alert→case escalation as the gated action; reusable gate pattern for future response actions ([[subprojects/2026-04-28-iris-escalation-gate/README]]) — shipped 2026-04-30
- [ ] **A3: Splunk lookup blocklist** — reuse A2's gate pattern; second action type (write IPs to a Splunk KV-store lookup that detection rules query). Triggers schema bump to v2 with structured `proposed_actions` (per [[decisions/0005-additive-ioc-type-schema-enhancement]]).

## Phase 2 — Detection content + capability expansion

- [x] **D1: Detection foundations — Sysmon + Atomic Red Team + Splunk SPL practice** — install Sysmon on the Windows 10 VM (SwiftOnSecurity-style config), install ART, run a tightly-scoped vertical slice (one MITRE technique → one Splunk saved search detecting it → one integration with the n8n webhook). Generates real endpoint telemetry the SOAR pipeline consumes; gives the project a detection-engineering surface to pair with the response-automation surface A1-A3 cover. **Pulled forward** ahead of A3 (see "Sequencing decision" below). — shipped 2026-04-30.
- [ ] **B: EDR layer** — LimaCharlie or Velociraptor, generates real endpoint telemetry beyond what Sysmon covers (file-system collection, response actions, threat-intel integration). May absorb or extend D1 depending on what D1 surfaces.
- [ ] **C: Detection engineering at scale** — Sigma rules, multiple detection types per MITRE tactic, MITRE coverage map. D1 is the seed; C is the build-out.

## Phase 3 — AI sophistication

- [ ] **E: Multi-agent triage** — router agent dispatches to specialist agents (malware, identity, network)
- [ ] **F: Case memory** — vector DB of historical alerts, RAG retrieval ("this looks like case #47")

## Phase 4 — Operational maturity

- [ ] **G: Observability** — Grafana dashboard of automation metrics
- [ ] **H: Purple team validation at scale** — automated weekly ART runs verifying detections still fire (D1 ships the manual version of this; H automates it)
- [ ] **I: Threat intel** — MISP integration

## Sequencing decision (2026-04-30)

D1 (detection foundations) is being pulled forward ahead of A3 (response action #2). This jumps the original Phase 1 → Phase 2 ordering. Rationale, briefly:

- **Job-prep priority.** SOC analyst interviews drill on EventCodes, process trees, IOC pivoting in SPL — skills that need richer telemetry than the current single brute-force saved search. D1 generates that telemetry; A3 doesn't.
- **A3's design pressure improves with multiple detections.** The schema-v2 `proposed_actions` design (per ADR 0005) is more coherent when designed against multiple action types fed by multiple detection types. A3 with only the brute-force detection has design pressure of one.
- **Architectural dependency unchanged.** A3 still needs A2's gate pattern (which is shipped) — D1 doesn't disrupt that. A3 just gets richer input data when it lands.

Doing D1 first does **not** mean abandoning A3; A3 is the architectural close of the A-series and still planned. The arc is: A1 → A2 → **D1** → A3 → (Phase 2/3/4 work).

## Non-goals (for now)

- Production use — this is a lab and portfolio piece, not for processing real customer data
- Scale beyond a single analyst's workflow
- Replacing commercial SOAR — the goal is to *understand* SOAR by building one
