# Selection-quality eval (opt-in, PAID, USER-run)

This is the eval harness for one specific question the offline test suite
cannot answer: **does the real model pick the right Splunk queries for a
given alert?**

Read this before you run anything -- `scripts/eval_selection.py` makes real
calls to the Anthropic API and (in the live branch) a real Splunk instance.
It is not free, it is not run in CI, and nothing in this repo triggers it
automatically. You run it by hand, on purpose, when you want a read on
selection quality.

## What the offline suite (Task 14) does and does NOT prove

`tests/test_scenarios.py` drives the real `investigate()` loop against a
**scripted** Anthropic client -- a fixed, hand-authored sequence of
tool-use turns played back in order. That's what makes it free, fast, and
deterministic, and it's the right tool for what it tests: given a decision
sequence, does the loop execute it correctly (dedup cache, MAX_TURNS,
MAX_QUERIES forcing conclude), and does `claims.py` / the verifier's
`scope_grounded` family ground the resulting evidence correctly (no
inflation, no absence-as-negative-proof, injection resistance).

None of that touches the one thing a scripted client can't test: whether
the model, left to decide for itself, actually **chooses** sensible
queries for a given alert and stops at a sensible point. That's a real
model judgment question, and the only way to measure it is to ask the real
model. That's what this harness is for. See spec
`docs/superpowers/specs/2026-07-11-honeypot-phase4-splunk-investigation-agent-design.md`
§8 ("Query-selection quality") for the full reasoning -- selection quality
is measured **only** by this harness plus the single live run described
there. The offline suite does not imply anything about it either way.

## What it scores

`SCENARIOS` in `scripts/eval_selection.py` is a small list of labeled,
synthetic honeypot alerts (repeated failed logons, a password-spray
pattern, a successful logon followed by encoded PowerShell, a repeat
offender IP). Each scenario reuses the existing v1 catalog only -- no new
Splunk query is added for this eval (see the module docstring for why:
a pivot query that emits a fresh `ip` row field would need a param-parse
guard that doesn't exist yet).

For each scenario, the harness runs `agent.investigate(...)` against the
real client N times (`--repetitions`, default 3) and scores each run:

- **Query selection**: did the agent actually run (successfully -- an
  `outcome=="ok"` catalog call, read from `result.scope_evidence.
  queries_run`) every query in that scenario's `expected_queries`? A
  param-rejected or Splunk-errored attempt doesn't count.
- **Conclusion**: did the agent call `conclude_investigation` with a
  non-empty summary, without getting cut off by the `MAX_TURNS` hard stop
  (`"max_turns_reached"` in `result.flags`)?

Both have to hold for that run to count as a pass. Results are aggregated
per scenario and overall, printed against `--threshold` (default 0.7), and
`main()` returns non-zero if the overall pass rate is below threshold.

## Running it

You need two things in your environment before you run this, loaded from
the gitignored creds file -- **never typed or pasted inline** (shell
history + chat both persist):

- `ANTHROPIC_API_KEY` -- from `../SOC-Automation-Project.md` (repo root,
  gitignored).
- Live Splunk connection details -- `SPLUNK_HOST`, `SPLUNK_PORT` (defaults
  to `8089`), `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_SCHEME`
  (defaults to `https`) -- same creds file.

Then, from `splunk-investigator/`, with the venv active:

```
./.venv/Scripts/python scripts/eval_selection.py --repetitions 3 --threshold 0.7
```

Both flags are optional; the values above are the module defaults. Every
`investigate()` call in the loop is a real, billed Anthropic API call
(model from `INVESTIGATE_MODEL`, default `claude-opus-4-8`) plus a read-only
search against your live Splunk instance -- with 4 scenarios x 3
repetitions that's 12 investigations, each up to `INVESTIGATE_MAX_TURNS`
(default 8) model turns. Budget accordingly before you run it, and don't
run it on a loop or a schedule.

## Not in CI, not automatic

`pytest` never triggers a paid call from this file. `tests/
test_eval_harness_import.py` only proves the module imports safely, that
`SCENARIOS` is well-formed, and that `main()`'s injected (offline) path
never falls through to the live branch -- it does not run the eval itself.
The live branch inside `main()` (the part that builds a real
`anthropic.Anthropic()` client and a real `splunklib` connection) is marked
`# pragma: no cover - live wiring` and is only ever reached when you invoke
the script directly with no factories, i.e. when a human runs it on
purpose.
