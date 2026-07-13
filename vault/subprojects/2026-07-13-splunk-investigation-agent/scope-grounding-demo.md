---
status: complete
updated: 2026-07-13
sub_project: Phase 4 (Splunk Investigation Agent)
related: [[README]]
---

# Scope-grounding ablation - SYNTHETIC fixture demonstration

> **SYNTHETIC / FIXTURE DATA.** Source IP `203.0.113.77` is RFC 5737 TEST-NET-3 (documentation range, never a real host). Scenario B's successful authentication is a fixture: `index=honeypot` is brute-force-only and cannot produce a real successful logon or post-exploit telemetry. This is NOT a real attacker incident.

This is the exact ablation the live Task-17 run performs - two `/verify` calls on the same triage result, differing only in whether the out-of-model `scope_evidence` bundle is supplied - proven offline through `build_report`, the same adapter the `/verify` endpoint calls. Each scenario isolates one grounding channel so the flip is unambiguous. Regenerate with `python -m grounding_service.scope_grounding_demo`; regression-locked by `grounding-service/tests/test_scope_grounding_demo.py` (5 passed).

## `scope_findings_grounded` - scope_findings_grounded_flip

A model's scope_findings are trusted only when they field-for-field match the harness's out-of-model scope_evidence; with no evidence to check them against, they fail CLOSED.

| Run | `scope_evidence` | `scope_findings_grounded` | overall `verification_passed` |
|-----|------------------|----------------|------------------------------|
| WITH scope  | supplied | **PASSED** | True |
| WITHOUT scope | `null` | **FAILED** | False |

**Attribution:** removing the grounding evidence flips this check `PASSED` -> `FAILED` and drops the whole report to Needs-Human.

## `severity_supported` - severity_supported_backing

A high severity with no malicious IOC and a non-hot tactic holds ONLY because grounded scope_evidence confirms a successful authentication; remove the evidence and the severity is no longer supported.

| Run | `scope_evidence` | `severity_supported` | overall `verification_passed` |
|-----|------------------|----------------|------------------------------|
| WITH scope  | supplied | **PASSED** | True |
| WITHOUT scope | `null` | **FAILED** | False |

**Attribution:** removing the grounding evidence flips this check `PASSED` -> `FAILED` and drops the whole report to Needs-Human.

---
Contrast with the live run: on real brute-force honeypot data neither channel moves (`severity_supported` rides the T1110 hot tactic; `scope_findings` was not populated by the live model), which is why this synthetic fixture - not the live ablation - is the deterministic grounding proof. See [[README]] "Honest outcome".
