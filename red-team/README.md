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

## Snapshots (`snapshots/*.json`)
The files under `snapshots/` are **real captured `honeypot-triage` n8n executions**, used as
byte-for-byte fidelity fixtures for the transform-chain port (`parse_alert` -> `build_opus_input`
-> `extract_result`). They are intentionally left un-edited so the port's parity tests compare
against genuine production output, not a hand-massaged copy.

As a consequence they carry a few **non-sensitive lab / vendor identifiers verbatim**, kept for
fidelity (the same decision already made for the kept attacker IPs elsewhere in this repo):

- `vm-soc-v2-splunk` — a non-routable internal lab VM hostname (no credentials, not reachable
  from outside the lab). It appears in raw input fields (`results_link`, `sid`, and the captured
  `opus_user_message`); the deployed workflow embeds the raw `results_link` into the model message
  *before* its scrub node runs, so the snapshot mirrors production exactly.
- `mydfir` — the maintainer's already-public lab handle (owner field / scheduler id).
- `falcon.us-2.crowdstrike.com` — a generic CrowdStrike Falcon vendor console hostname (with a
  synthetic `/synthetic-path-validation` placeholder path, not a real detection id). It exposes no
  tenant, credential, or PII; the SOC vendor stack (CrowdStrike Falcon, us-2 region) is already
  named intentionally in this repo.

These are **not** scrubbed here on purpose: editing the snapshot JSON would break the port's
byte-parity guarantee, and adding scrub logic to `extract_result.py` would diverge from the
deployed JS it faithfully ports (the deployed scrub only rewrites the derived outbound
`detail_link`, never the input-region fields). If any of these ever needs to be treated as
sensitive, hand-edit the snapshot inputs — do **not** change the port's scrub logic.
