# Honeypot Phase 1 build, session 9 handoff (2026-07-02): the 3 JS to Python ports are DONE

**The whole transform layer of the red-team harness is now built.** Tasks 2, 4, 5, 6 shipped this session
via subagent-driven-development. This supersedes the session-8 handoff
(`2026-07-02-SESSION8-BUILD-COMPLETE-HANDOFF.md`) for "what to do next." Read order:

1. **This file** (what session 9 finished, exact resume state, the one clean next task).
2. **The ledger** `.superpowers/sdd/progress.md` (git-ignored scratch, on disk). Its "SESSION 9" block plus the
   "PORTS COMPLETE" marker is the durable per-task recovery map. Trust it and `git log` over any recollection.
3. **Plan v2.1** `docs/superpowers/plans/2026-07-01-honeypot-phase1-redteam-harness-baseline.md` (PARENT
   workspace `f:\Claude_Code\Skills-Learning\docs\superpowers\`, NOT a git repo). The remaining tasks (12, 13,
   15, 14b) are fully specified there. Global Constraints are at the top (plan line 21).
4. **Spec v2.1** `docs/superpowers/specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` (PARENT).
5. `MASTER-CHECKLIST.md` (this dir) for the whole-project picture; its Phase 1 block is current.

> Writing conventions: casual, conversational, slightly technical. No em dashes in prose. Lead with action.
> Prefer USER hands-on for anything on the honeypot/VMs. No inline secret paste (load from the gitignored
> creds file, on a local machine, never on the honeypot).

---

## STATE AT PAUSE

- Branch **ai-upgrade**, HEAD **`0f86daf`**. **20 commits ahead of the PUBLIC `origin/ai-upgrade`, NOT
  pushed.** User decision stands: keep local until Plan 1 is runnable (the repo is public, so a push would
  publish a half-built harness). A push, whenever it happens, gets a secret/IP scrub review first.
- Full red-team suite **85/85 pristine** (`cd red-team && .venv/Scripts/python -m pytest -q`). Re-verified at
  session end.
- Working tree carries only doc changes (this handoff, the SESSION7/SESSION8 handoffs, `MASTER-CHECKLIST.md`,
  and the pre-existing `2026-07-01-NEXT-SESSION.md` noise). No uncommitted code. `git diff --stat b266570..0f86daf`
  is exactly the 4 port files (input_builder.py, extract_result.py, and their tests).
- Never `git add -A`; exact-path adds only. Every commit ends with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## WHAT SESSION 9 BUILT

**Task 2, hands-on snapshot capture (commit `b266570`).** Two real `honeypot-triage` executions pulled from
n8n history (Splunk run 275, Falcon run 281) into `red-team/snapshots/{splunk,falcon}_baseline.json`, six
load-bearing fields each. The VM is deallocated again. These are the ORACLE the ports validate against and are
never regenerated from the port.

**Tasks 4, 5, 6, the JS to Python ports** via `superpowers:subagent-driven-development` (fresh sonnet
implementer + independent sonnet reviewer per task, TDD, byte-fidelity against the snapshots):

- **T4** `harness/input_builder.py` `parse_alert` (commit `5513e9b`), port of `JS_PARSE`
  (build_honeypot_triage_workflow.py:88-126). 3 tests. Review clean.
- **T5** same file: `build_opus_input` + `splunk_body_from_case` + `falcon_body_from_case` (commit `71b9b67`),
  port of `JS_OPUSINPUT` (lines 140-173); `falcon_body_from_case` is a one-line reuse of
  `grounding_service.falcon.map_alert`. 6 tests. Review clean.
- **T6** `harness/extract_result.py`: `NoToolCall` + `extract_result` (commit `7cac133`), port of `JS_EXTRACT`
  (lines 175-304). Review found 1 Important (a `KeyError` crash on a malformed IOC where the JS degrades to a
  placeholder), fixed in `0f86daf` (graceful `.get()` at both the `alert_iocs` and `iris_description` sites +
  regression test), then re-reviewed clean. 11 tests.

## THE FACTS THE T12/T13 BUILDER NEEDS (from the snapshots + the ports)

- **`opus_usage` is `{input_tokens:0, output_tokens:0}` in both snapshots** because the deployed n8n langchain
  Anthropic node does not surface token usage. So `verify_body.run_meta` tokens are 0. `extract_result` threads
  whatever `usage` you pass; the harness's own live `model_client` (T7, already built) gets REAL usage from the
  Anthropic API for the live run (T15). The snapshots' zeros are only for the offline port-parity tests.
- **Splunk detail-link was reconciled** during Task 2: the live run scrubbed the deep-link host to the real
  Splunk public IP, but the COMMITTED `extract_result` scrubs `vm-soc-v2-splunk` to `x.x.x.x`
  (build_honeypot_triage_workflow.py:244-246). The snapshot's `extract_result_output` link fields hold
  `x.x.x.x` so the port matches committed behavior (and the SOC infra IP stays out of the public repo). The
  input `results_link` in `webhook_body`/`build_opus_input_output` keeps the raw internal host on purpose.
- **Attacker source IPs are kept PUBLIC by user decision** (45.142.193.166 Splunk, 2.57.121.25 Falcon). Only
  SOC infra IPs (the n8n + Splunk public IPs) were stripped/reconciled.
- **Defensive-fill deltas:** the Splunk model output omitted only `investigation_notes`; the Falcon output
  omitted both `investigation_notes` and `recommended_actions`. `extract_result` back-fills empty structure
  only, never overwriting present values; `verify_body.result` carries the post-fill state.
- **`parse_alert`'s `body` param is already the unwrapped webhook body** (equivalent to the JS
  `$input.first().json.body`); do not unwrap another `.body`.

## IMMEDIATE NEXT ACTION, one clean offline task

**Build Task 12 (`runner.py`) via `superpowers:subagent-driven-development`, exactly as this session did.** It
wires the already-built pieces: `model_client` (live Opus call + outcome classifier) + `retriever` (top_k=8) +
`input_builder` (parse + build) + the `triage_verifier` + `extract_result` + `scorer` into `run_case` plus the
K-trial loop, handling refusal / NO_TOOL_CALL / PARTIAL / INVALID per the spec. Plan Task 12 is at plan line
923. Then, in order (all specified in plan v2.1):

- **T13 `report.py`** (`build_baseline_report`, per-class grouping by `case.id` prefix, Clopper-Pearson CIs),
  plan line 1024. Offline, buildable right after T12.
- **T14b held-out corpus** in `attacks/held_out/`. MUST be authored by a DIFFERENT subagent that never saw the
  hardening discussion (it is the headline for Plan 2 levers). Dispatch a blind subagent.
- **T15 the live baseline run = Gate-3**, plan line 1111. Needs a live `ANTHROPIC_API_KEY` (user loads it from
  the gitignored creds file on a local machine, never inline, never on the honeypot) and a local Qdrant seeded
  via `grounding-service/scripts/ingest_attack.py`. Produces the committed baseline report = Gate-3.
- **Final whole-branch adversarial review** after the build completes (the SDD capstone; see below).

T12 and T13 are fully offline and need nothing from the user. T15 is the natural next live checkpoint.

## OPEN ITEMS FOR THE FINAL WHOLE-BRANCH REVIEW (do not lose these)

- **Minor (fidelity):** `build_opus_input` uses `t.get('tactics', [])`, which only coalesces an ABSENT key,
  whereas the JS `(t.tactics || [])` coalesces any falsy incl `null`. A `retrieve` output with `tactics: null`
  would `TypeError` on `', '.join(None)`. Not hit by the snapshots. Same `.get(key, default)` shape exists in
  `parse_alert` (`body.get("result", {})`). Fix consistently across `input_builder.py` at the final review
  (`t.get('tactics') or []`, and audit parse_alert's analogous `||` ports), not piecemeal.
- The per-task Minor roll-up from session 8 is in the ledger; none block merge.

## HOW TO RESUME (subagent-driven-development)

- The SDD scripts are at
  `C:\Users\Owner\.claude\plugins\cache\claude-plugins-official\superpowers\6.1.0\skills\subagent-driven-development\scripts\`:
  `task-brief PLAN_FILE N` (extract a task's brief to a file), `review-package BASE HEAD` (build the reviewer's
  diff file). Both print the path they wrote.
- Per task: dispatch a fresh implementer (sonnet is the right floor for these mechanical-but-careful tasks;
  the plan text carries the full spec), then generate the review package with BASE = the commit before the
  implementer (NOT `HEAD~1`), dispatch an independent reviewer, dispatch a fix subagent for any
  Critical/Important, re-review, mark complete in the ledger.
- Model note: sonnet handled all of T4/5/6 impl + review cleanly. Use opus only for the final whole-branch
  review (the SDD capstone) or if a task turns out to need design judgment.
- Conventions: exact-path `git add`; the commit trailer above; run pytest from inside `red-team/`
  (`.venv/Scripts/python -m pytest -q`); cross-package deps (`grounding_service`, `triage_verifier`,
  `qdrant_client`) are out-of-band editable installs in the venv, NOT in `red-team/pyproject.toml` (by design,
  do not "fix").

## WHAT ASSURES THIS WORK IS CORRECT (already done) AND WHAT STILL REMAINS

Already in place: every port was built TDD-first and validated BYTE-FOR-BYTE against real captured n8n
executions (not hand-authored, so the harness cannot test itself); an independent reviewer per task did a named
line-by-line fidelity check against the JS source, confirmed the snapshot tests are non-tautological, and ran
named risk checks (mutation safety on T6); T6's one real crash-on-malformed-input finding was caught and fixed
and re-reviewed; the snapshots themselves were assembled through `json.loads` + internal-consistency assertions
+ the link reconciliation; the full suite is green (85/85) and all code is committed.

Still remaining (by design, not gaps): the **final whole-branch adversarial review** is the comprehensive gate
and runs AFTER T12/T13 land (it is premature now); **T15's live baseline run** is itself an end-to-end
validation of the whole harness against the live model; and building **T12** exercises all the ports together
for the first time (integration validation). The one parked Minor above gets fixed at the final review.
