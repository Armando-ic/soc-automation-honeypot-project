---
status: complete
updated: 2026-07-13
sub_project: Phase 4 (Splunk Investigation Agent)
related: [[scope-grounding-demo]], [[../../log]]
---

# Phase 4 - Splunk Investigation Agent (grounded, entity-scoped triage)

A bounded, entity-scoped Splunk investigation agent that grounds triage severity and scope in **real query results, out of model control**. It runs inside the honeypot triage pipeline:

`Splunk alert -> n8n -> grounding-service /investigate -> Opus triage -> /verify -> IRIS + Discord`

On a real alert, `/investigate` runs a short, tool-limited agentic loop (`MAX_TURNS=8` / `MAX_QUERIES=4`) over a **fixed catalog** of entity-bound Splunk lookups, and emits a FLAT set of grounded scope claims (`scope_evidence`). Those claims travel to the verifier **out of model control**; the verifier grounds the severity + scope narrative in them and **fails closed** if the evidence does not back the claims.

Design goal: the model can narrate, but it cannot invent scope. Scope claims must be backed by real, out-of-model query results or the report drops to Needs-Human. Severity grounding is only partial today: it holds except on hot tactics like T1110, which pass on the tactic alone, so grounding does not yet cap an over-escalated severity (see Honest outcome for what the live run actually showed).

Operate / reproduce: [Task-17 live-run runbook](../../../infra/honeypot/splunk-investigator-live-run.md) (Parts 0-7, hands-on, USER-driven). Spec + plan live in `.superpowers/sdd/`.

---

## The live run (2026-07-13, one paid alert)

One real honeypot brute-force alert was fired end-to-end against the deployed pipeline. The attacker source IP is redacted to `x.x.x.x` throughout (real values stay in the gitignored `splunk-investigator/reports/`; only this scrubbed page is committed).

### Grounded scope claims - out-of-model ground truth (`scope_evidence`)

Computed from real Splunk results by the fixed lookup catalog, not by the model:

| Claim | Value | Reading |
|---|---|---|
| `auth_outcome` | 665 failed / **0 successful** logons | authentication never succeeded - no compromise |
| `distinct_targets` | 1 account (`Administrator`) | focused credential-access, not a broad spray |
| `repeat_offender` | first seen ~0.9 days ago, 1 day active | newer short-burst source, not an established offender |
| `encoded_powershell` | 0 on `vm-honeypot-win` | no known follow-on tradecraft |
| `processes_by_user` | 0 process-creation events | no hands-on-keyboard / post-auth activity |

With `success_count = 0`, `distinct_targets` / `repeat_offender` are presented as **brute-force breadth** ("one account hammered from this source over ~1 day"), never as compromise.

### Advisory transcript - model narrative, NOT ground truth

The agent ran the catalog in entity-bound order (3 turns, 5 queries, then `conclude_investigation`) and produced this advisory summary (attacker IP redacted):

> SCOPING RESULT: RDP/SMB brute force against user 'Administrator' on host 'vm-honeypot-win' from external IP `x.x.x.x`. Assessment: FAILED brute force, NO evidence of compromise. ... 665 failed / 0 successful logons across both -24h and -7d windows. ... only 1 distinct target account (Administrator). ... 0 Sysmon process-creation events; 0 encoded-PowerShell invocations. ... Note: no tool errors were encountered, so 'absent' findings here reflect genuine zeroes rather than unknowns.

The transcript is **rows-free by design** (`_summarize_no_rows`): each turn records the entity-bound query + params + a `{outcome, row_count}` summary, never raw event rows. Raw rows stay inside the loop and never reach the published surface.

---

## The grounding mechanism (proof)

On brute-force-only honeypot data the **live** severity ablation cannot move (see Honest outcome), so the grounding-flip is proven deterministically by an **offline synthetic fixture** - the same `/verify` adapter the live pipeline uses, run on two labelled-synthetic scenarios: [[scope-grounding-demo]].

Removing `scope_evidence` flips both `scope_findings_grounded` and `severity_supported` **PASSED -> FAILED** and `verification_passed` **True -> False**. Regression-locked by `grounding-service/tests/test_scope_grounding_demo.py` (5 passed); regenerate with `python -m grounding_service.scope_grounding_demo`. The fixture is clearly labelled synthetic (RFC 5737 TEST-NET-3 IP, fixture successful auth) and is never presented as a real incident.

---

## Honest outcome

- **Live "a real incident changed severity" criterion: NOT MET.** `index=honeypot` is brute-force only (4625 failed logons; the single in-window 4624 was a benign local SYSTEM service logon, confirmed not a compromise). `severity_supported` passes on the **T1110 credential-access hot tactic alone**, and a grounded HIGH via scope needs an auth `success_count > 0` that brute-force data never yields. The live ablation (WITH vs WITHOUT `scope_evidence`) produced **identical** check results - no delta. Expected and documented.
- **Honest limitation the run surfaced:** the triage **over-escalated** the failed brute-force to `critical` ("suspected active-compromise attempt") on the hot-tactic + malicious-IP calibration, and the verifier **passed** it. The grounded 0-success did **not** cap the severity. A seasoned analyst would rate a failed honeypot brute-force low/informational. Takeaway: grounding makes the **scope narrative** accurate; it does **not yet cap** a hot-tactic severity.
- **`scope_findings` prompt-populate gap (T13-1):** the live model did not populate `scope_findings` (the verbatim-copy field), so `scope_findings_grounded` was **vacuous** live. The offline demo carries the grounding proof.
- **What the live run DID demonstrate (met):** the deployed agent reachably investigates real alerts, runs entity-bound queries in a bounded loop, produces an honest brute-force-breadth scope narrative with grounded claims, and (after the fix below) the verifier evaluates the full grounded check family on live data.
- No synthetic events were written to live Splunk; no self-authored or synthetic data is presented as a real attacker incident.

---

## Deploy bug found + fixed (test-first)

The first live `/verify` calls all fail-closed with `verifier_error`:

```
verifier raised: [Errno 2] No such file or directory: '/app/JSON/honeypot-triage.json'
```

**Root cause:** the verifier loads `config.prompt_path` (`JSON/honeypot-triage.json`) eagerly at verify time (`verify_adapter.py -> TriageVerifier.from_paths`), but the Dockerfile copied only the four package dirs, never `JSON/`. In the container the path resolved to `/app/JSON/honeypot-triage.json` (absent) -> `FileNotFoundError` -> fail-closed.

**Fix (commit `c08b76a`):** `COPY JSON/honeypot-triage.json` into the image + a `test_deploy_wiring` regression guard. Live re-verified at $0: the exact captured run now passes the full 14-check family (`schema_valid`, `mitre_*`, `severity_supported`, `scope_findings_grounded`, `scope_notes_honesty`, `enrichment_grounded`, ...), `verification_passed: True`.

The fail-closed behaviour is the intended safety net - a missing dependency did **not** produce a bogus approval. The fix is what lets the grounded verification actually run in production.

---

## Invariants (do not break)

- `/investigate` transcript is **rows-free** (raw rows stay in-loop, never on the published surface).
- FLAT `{"type": <name>, **fields}` claim shape.
- `scope_evidence` reaches `/verify` **out of model control**; `scope_grounded` **fails closed**.
- `event_time` anchors every query window, never wall-clock.
- LIVE index allowlist = `honeypot` only.
- The deployed image must include `JSON/honeypot-triage.json` (guarded by `test_deploy_wiring`).

## Suites (all green)

grounding-service 111 + 2 known falcon reds · splunk-investigator 117+1skip (own venv) / 122 (cross-venv) · triage-verifier 68 · malware-triage 105 · builder 20.
