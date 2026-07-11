# fixtures/scenarios

Hand-authored, **labeled SYNTHETIC** end-to-end scenario fixtures for
`tests/test_scenarios.py` (Phase 4 Task 14). Each of these is a self-authored
test scenario, not a captured real attacker incident.

Each scenario subdirectory holds:

- `alert.json` -- the honeypot alert dict passed as `investigate()`'s
  `alert` positional arg (`src_ip`, `host`, `user`, `event_time`,
  `alert_text`).
- `script.json` -- the scripted Anthropic tool-use turns
  (`[{"tool": <catalog query name or "conclude_investigation">, "input": {...}}, ...]`)
  the fake client plays back in order, one per `client.messages.create(...)`
  call.
- `<query_name>.json` -- one Splunk `output_mode=json` results envelope per
  catalog query the script actually calls, same shape as
  `fixtures/envelopes/*.json`. The test's fixture-backed `run_catalog_query`
  stub loads this file and routes it through the REAL
  `splunk_investigator.splunk_client.parse_envelope`, so the
  error/capped/ok outcome mapping is exercised, not hand-asserted.

## Scenarios

- `success_plus_encoded_ps/` -- a successful logon plus encoded PowerShell
  on the host; grounds a `severity="critical"` triage (needs BOTH claims).
- `no_success_minimal/` -- all-fail auth, no process/encoded queries;
  proves the evidence bundle isn't inflated and a `severity="high"` claim
  with no success backing fails the gate.
- `lone_success/` -- exactly one successful logon, no process/encoded
  claim; supports `severity="high"` but not `severity="critical"`.
- `soft_error_fatal/` + `soft_error_ok_zero/` -- a paired contrast: a FATAL
  Splunk envelope (outcome="error") emits NO claim and is absent from
  `queries_run`, versus an ok-but-0-row envelope, which DOES emit a real
  `auth_outcome(success_count=0)` negative finding and IS recorded. Pins
  the absence-vs-unknown distinction that `claims.py` enforces.
- `injection/` -- `alert_text` seeds an off-scope IP (`8.8.8.8`) and a
  malicious user string (`"; | delete"`); the scripted client tries to
  query both. `params.py`'s entity-binding/charset gate must reject both
  before `run_catalog_query` is ever called for them.
