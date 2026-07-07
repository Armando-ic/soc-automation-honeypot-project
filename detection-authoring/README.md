# detection-authoring

Phase 2 of the honeypot agentic-SOC project: **RAG-grounded, gate-verified detection-as-code**. Claude Opus drafts a Sigma rule for a MITRE ATT&CK technique, grounded on the ATT&CK corpus, and a deterministic 4-tier gate decides whether the draft is good enough to trust, without trusting the LLM.

The gate:

- **T1** valid Sigma (pySigma parse)
- **subset** the rule stays inside the owned matcher's supported subset
- **T2** compiles to Splunk SPL
- **T3** fires on the frozen positive corpus (true positives)
- **T4** stays quiet on the frozen benign baseline (no false positives)

A rule only lands in the catalog if all four pass. See the per-technique write-ups in `../vault/detections/`.

## Install

This package depends on its sibling `grounding-service` (the ATT&CK RAG retriever + embedder), which is not published to PyPI. Install it editable first, then this package:

```bash
python -m venv .venv
# activate: .\.venv\Scripts\activate  (PowerShell)  or  source .venv/bin/activate  (bash)
pip install -e ../grounding-service
pip install -e ".[dev]"
```

Without the `grounding-service` install, `pytest` cannot even collect (`tests/conftest.py` imports it for the offline retriever fixtures).

## Run the tests (offline, no network, no API key)

```bash
python -m pytest -q
```

Every tier of the gate is a pure function of the candidate YAML and the frozen corpus, so the whole suite runs offline with no Qdrant and no Anthropic calls.

## Run the live authoring loop (paid, needs Qdrant + an API key)

```bash
# prerequisites:
#   1. a local Qdrant seeded with the ATT&CK corpus (see ../grounding-service)
#   2. ANTHROPIC_API_KEY in the environment
python -m scripts.run_authoring --technique T1059.001 --technique T1059.003 --k 5 --out reports/authoring-run.md
```

Each trial is one `claude-opus-4-8` call to draft a rule, then the free deterministic gate to judge it. Gate-passed rules are written to `rules/<technique>.yml` (plus the compiled SPL and a per-rule gate report); the aggregate pass-rate report goes to `--out`. Generated `rules/` and `reports/` are gitignored so stray runs do not litter the repo.

## Matcher faithfulness

T3/T4 use an owned Sigma matcher over a constrained subset (rather than coupling to pySigma's version-sensitive internal AST). `scripts/CROSSCHECK.md` describes the one-time cross-check against Zircolite (a real community Sigma engine) that proves the owned matcher agrees with real Sigma semantics on the whole frozen corpus.
