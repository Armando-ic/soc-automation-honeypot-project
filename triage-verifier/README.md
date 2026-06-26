# triage-verifier (honeypot Phase 0C)

A pure, offline, test-driven **credibility-gate verifier** over the SOC pipeline's
`submit_triage_result` output, plus a lightweight **eval harness**. Ports the SOP-RAG verifier
pattern to SOC triage. Wired into the live SOAR path in Plan 0D.

## What it checks (8 deterministic checks, all must pass)
1. `schema_valid` — validates against `schema/submit_triage_result.json`
2. `iocs_enriched_grounded` — every enriched IOC was actually observed in `iocs`
3. `ioc_type_consistent` — `ioc_type` matches the value's shape and bucket
4. `mitre_id_exists` — technique id is in the bundled ATT&CK reference
5. `mitre_name_match` — technique name matches ATT&CK
6. `mitre_tactic_valid` — tactic is valid for the technique
7. `severity_supported` — high/critical needs a malicious/suspicious IOC or a high-severity tactic
8. `verdict_sourced` — a malicious/suspicious verdict must cite a source

Plus an **advisory judge** that always returns `needs_human` (never auto-approves), and two
**deferred** retrieval-grounding checks (`mitre_in_retrieved`, `enrichment_grounded`) that report
`NOT_APPLICABLE` until Plan 0D supplies Qdrant + live-enrichment context.

## Run
```bash
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest tests/ -v     # unit + fixture tests
.venv/Scripts/python eval.py                 # the eval gate (nonzero on mismatch)
```
Refresh the ATT&CK table: `python scripts/regen_attack_reference.py`.

## Honest limitations
- Grounds against the model's own observed-IOC list + a static ATT&CK table — **not** live
  retrieval yet (that is `mitre_in_retrieved`/`enrichment_grounded`, wired in 0D).
- `severity_supported` is a heuristic (the `HIGH_SEVERITY_TACTICS` set), not a calibrated model.
- The judge is the **same model class** as the drafter (correlated-failure risk) — advisory only.
- Verifies top-level technique ids only (no sub-technique argument semantics).
- `eval.py` is the gate: no verifier/schema/prompt change ships unless it stays green.
