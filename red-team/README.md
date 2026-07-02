# red-team (honeypot Phase 1)

Production-faithful adversarial red-team harness for the honeypot SOC pipeline. It replays and
mutates real alert scenarios against the same `submit_triage_result` contract the live n8n
workflow exercises, then scores the pipeline's verdicts through `triage-verifier` and
`grounding-service` (installed editable below) instead of a separate ad hoc grader. The goal is
to find prompt-injection, evasion, and grounding-failure cases before they show up in production,
not to test a toy copy of the pipeline.

## Run
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e "../triage-verifier"
.venv/Scripts/python -m pip install -e "../grounding-service"
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest tests/ -v
```
Note: `.venv/Scripts/` is the Windows path, on Linux/macOS use `.venv/bin/`.

## Live campaign (opt-in)
The full adversarial campaign against the live model is opt-in, not part of the default test run.
It needs `ANTHROPIC_API_KEY` set and a local Qdrant instance up (same one `grounding-service`
uses for retrieval), since cases are scored end to end through the real grounding and
verification path.
