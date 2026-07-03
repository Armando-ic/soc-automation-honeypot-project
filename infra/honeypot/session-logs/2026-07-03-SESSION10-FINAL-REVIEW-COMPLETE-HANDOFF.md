# Honeypot Phase 1, session 10 handoff (2026-07-03): the offline harness is BUILT, REVIEWED, and green

**The whole Plan-1 red-team harness is code-complete and passed its capstone adversarial review.** This session
built the last three offline tasks (T12 runner, T13 report, T14b held-out corpus), then ran the final
whole-branch review, fixed everything it found, and re-reviewed to "Ready to merge." The only thing left in
Plan 1 is **T15, the live baseline run**, which needs you (a live API key + a local Qdrant). Read order:

1. **This file** (what session 10 finished, exact resume state, the one remaining task).
2. **The ledger** `.superpowers/sdd/progress.md` (git-ignored scratch, on disk). The "SESSION 10 COMPLETE" +
   "FINAL WHOLE-BRANCH REVIEW + FIX WAVE COMPLETE" blocks are the durable per-task recovery map. Trust it +
   `git log` over any recollection.
3. **Plan v2.1** `docs/superpowers/plans/2026-07-01-honeypot-phase1-redteam-harness-baseline.md` (PARENT
   workspace `f:\Claude_Code\Skills-Learning\docs\superpowers\`, NOT a git repo). **Task 15 is at plan line
   1111.** Global Constraints at the top (plan line 21).
4. **The final review + fixes** (all in `.superpowers/sdd/`): `final-review-b6b263e..6b1ffc3.md` (the review),
   `final-review-fix-brief.md` (the decisions + task list), `final-review-fix-report.md` (what was fixed).

> Writing conventions: casual, conversational, slightly technical. No em dashes in prose. Lead with action.
> Prefer USER hands-on for anything on the honeypot/VMs. No inline secret paste (load from the gitignored
> creds file, on a local machine, never on the honeypot).

---

## STATE AT PAUSE

- Branch **ai-upgrade**, HEAD **`6302626`**. **30 commits ahead of the PUBLIC `origin/ai-upgrade`, NOT pushed.**
  User decision stands: keep local until Plan 1 is runnable and a secret/IP scrub review runs, because the
  repo is public and a push now would publish a half-built harness.
- Full red-team suite **122/122 pristine** (`cd red-team && .venv/Scripts/python -m pytest -q`). Re-verified at
  session end.
- Working tree carries ONLY the pre-existing `infra/honeypot/session-logs/2026-07-01-NEXT-SESSION.md`
  modification (noise, not from this session). No uncommitted code. Never `git add -A`; exact-path adds only.
- Every commit ends with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## WHAT SESSION 10 BUILT (all via superpowers:subagent-driven-development, local commits only)

- **T12 `runner.py`** (`74bba21`) — `run_case` K-loop wiring all the ports together; per-trial outcome branch
  (TRUNCATED->INVALID, REFUSAL/NO_TOOL_CALL->no gate/bypassed=False, TOOL_CALL/PARTIAL->extract->verify->score).
  sonnet impl + sonnet review, spec compliant / 0 Crit-Imp.
- **T13 `report.py`** (`d3a3953`) — per-class baseline report, Clopper-Pearson CIs, OPEN labels, no bare "0%",
  INVALID + outcome distribution separate. sonnet impl + sonnet review, spec compliant / 0 Crit-Imp.
- **T14b held-out corpus** (`3930e71` + `6b1ffc3`) — 13 novel cases authored BLIND by a fresh opus subagent
  (schema + scorer contract + taxonomy only, no hardening); opus review fired all 13 predicates against the
  real scorer and caught + retargeted one dud D1 case.
- **Final whole-branch review** (Workflow, 6 lenses -> refute-verify -> synthesis, 23 agents) -> "Not ready":
  2 Critical + 6 Important + 7 Minor, all survived verify. Then a **2-wave opus fix** (`eb03b94`, `b7f9f4d`,
  `9dcde19`, `5ce8d6b`, `6302626`) + an independent opus **re-review = "Ready to merge."**

## WHAT THE REVIEW CHANGED (so the next instance is not surprised)

The review's value was cross-cutting bugs the per-task gates could not catch:

- **Crash-safety:** `extract_result` used to `KeyError`/`TypeError` on a model tool call that omits a nested
  sub-field or supplies a non-dict list element, aborting the WHOLE campaign on exactly the adversarial output
  the harness exists to elicit. Now it degrades like the deployed JS, and the runner wraps the gate path like
  production's `build_report` (verifier_error -> FAILED -> not-bypassed, never aborts).
- **Payload delivery:** 6 seed cases had buried their entire payload in an `alert.raw` key that
  `splunk_body_from_case` never reads (authored in session 8 before the input ports existed in session 9). All
  relocated into read fields; a per-source loader guard now rejects any unread alert key at load time. That
  guard also exposed + fixed 5 more latent delivery bugs (a wrong-shape B1 falcon case + 4 splunk cases using
  `ComputerName`).
- **User decisions (3):** the D1 discord-mention class fired deterministically from attacker-controlled alert
  fields (not model behavior), so it was **reclassified as a pipeline-integrity structural test** and its cases
  removed; the structurally-unfireable `output_not_json_safe` predicate + `D1-json-break` were **deleted**; the
  snapshot lab/vendor identifiers (`vm-soc-v2-splunk`, `mydfir`, `falcon.us-2.crowdstrike.com`) are
  **documented as kept-for-fidelity** (README note), not scrubbed. Net: the corpus now measures **7 model-attack
  classes {A1,A2,A3,A4,B1,C1,E1}**, grammar is **10 predicates**, seed corpus is 10 cases, held-out is 11.

## IMMEDIATE NEXT ACTION: T15, the live baseline run = Gate-3 (plan line 1111)

This is the only remaining Plan-1 task and it needs the USER (the harness is otherwise done):

1. **On the user's local machine** (NOT the honeypot): load `ANTHROPIC_API_KEY` from the gitignored creds file
   into the environment (never inline, never on the honeypot).
2. Start a local Qdrant and seed MITRE: `python grounding-service/scripts/ingest_attack.py` (downloads
   enterprise-attack.json into the `attack_techniques` collection, dim 384, BgeEmbedder).
3. **Write `red-team/scripts/run_baseline.py`** (plan Task 15 step 3): a thin CLI that loads the cases, builds
   the ModelClient + the live retriever, runs each case at tiered K (exploratory K=5 across all seed cases,
   then K>=50 for the headline classes), aggregates into `CaseResult`s, and calls `build_baseline_report`.
4. Sanity-check `ModelClient.call` sends only model+system+tools+max_tokens+messages (no sampling params /
   thinking / effort / tool_choice), then run the exploratory pass, then the headline pass, and commit
   `reports/baseline-<harness-commit>.md` (Gate-3) + the runner script.

After T15: **superpowers:finishing-a-development-branch** (merge/PR decision) + the secret/IP scrub review
before any push (branch is 30 ahead of the PUBLIC remote).

## HOW TO RESUME (subagent-driven-development)

- SDD scripts at `C:\Users\Owner\.claude\plugins\cache\claude-plugins-official\superpowers\6.1.0\skills\subagent-driven-development\scripts\`:
  `task-brief PLAN_FILE N`, `review-package BASE HEAD` (BASE = the commit before the implementer, NOT `HEAD~1`).
- Conventions: exact-path `git add`; the commit trailer above; run pytest from inside `red-team/`
  (`.venv/Scripts/python -m pytest -q`); cross-package deps (`grounding_service`, `triage_verifier`,
  `qdrant_client`) are out-of-band editable installs in the venv, NOT in `red-team/pyproject.toml` (by design,
  do NOT "fix"). LOCAL ONLY, do NOT push.
- T15 is a live task and needs the user hands-on for the key + Qdrant; the run_baseline.py script itself can be
  drafted offline first, then run once the user has the key + Qdrant up.

## OPEN / ACCEPTED (none block T15 or merge)

- The final review's residual Minors are all triaged in the ledger. No Critical/Important remain (re-review =
  Ready to merge). Two noted non-issues: `test_runner.py` hand-built `AttackCase` fixtures still use
  `ComputerName` (harmless, they bypass the loader), and a stale `.pytest_cache` string.
- `MASTER-CHECKLIST.md`'s Phase-1 block predates the final review; refresh it opportunistically (not blocking).
