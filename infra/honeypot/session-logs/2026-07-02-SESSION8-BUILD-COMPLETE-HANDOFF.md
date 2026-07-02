# Honeypot Phase 1 build — session 8 handoff (2026-07-02): 8 snapshot-independent tasks DONE

**The snapshot-independent half of Plan 1 is built, reviewed, fixed, and green.** This supersedes the
session-7 handoff (`2026-07-01-SESSION7-BUILD-HANDOFF.md`) for "what to do next." Read order:

1. **This file** (what session 8 finished + exact resume state + the one thing that unblocks the rest).
2. **The ledger** `.superpowers/sdd/progress.md` — the durable per-task recovery map. Its
   "BUILD COMPLETE 2026-07-02" block + the Minor roll-up are the source of truth. Trust it and `git log`
   over any recollection. (Git-ignored scratch; `git clean -fdx` would wipe it — recover from `git log`.)
3. **The final-review report** `.superpowers/sdd/final-review-b6b263e..72a6c48.md` + the fixes report
   `.superpowers/sdd/final-review-fixes-report.md`.
4. **Plan v2.1** `docs/superpowers/plans/2026-07-01-honeypot-phase1-redteam-harness-baseline.md`
   (PARENT workspace, non-git) — the deferred tasks (2, 4, 5, 6, 12, 13, 15) are specified here.
5. **Spec v2.1** `docs/superpowers/specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` (PARENT).
6. `infra/honeypot/session-logs/2026-07-01-NEXT-SESSION.md` (session-6 handoff) for infra/VM state,
   conventions, and the Falcon/Splunk/n8n specifics.

> Writing conventions: casual, conversational, slightly-technical. No em dashes / spaced-hyphen dashes in
> prose. Lead with action. Prefer USER hands-on for anything on the honeypot/VMs. No inline secret paste.

---

## STATE AT PAUSE

- Branch **ai-upgrade**, HEAD **`4d7811f`**. **15 commits ahead of the PUBLIC `origin/ai-upgrade`
  (`b6b263e`), NOT pushed.** User decision (2026-07-02): **keep local for now** — do NOT push until Plan 1
  is runnable (or the user says so). The repo is public, so a push publishes a half-built harness.
- Full suite **65/65 pristine** (`cd red-team && .venv/Scripts/python -m pytest -q`).
- Working tree carries only pre-existing session-log noise (`2026-07-01-NEXT-SESSION.md` modified,
  `2026-07-01-SESSION7-BUILD-HANDOFF.md` + this file untracked). `red_team.egg-info/` is now gitignored.
- Never `git add -A`; exact-path adds only. Every commit ends with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## WHAT SESSION 8 BUILT (range b6b263e..4d7811f)

8 snapshot-independent tasks via `superpowers:subagent-driven-development` (fresh implementer + reviewer
per task; opus for the scorer/corpus/final-review, sonnet elsewhere):

- **T1** scaffold `red-team/`; **T3** `harness/system_prompt.py` (loads deployed prompt + tool schema,
  byte-fidelity; + `__main__` guard on the generator + banner on the drifted `triage-honeypot.md`);
  **T7** `harness/model_client.py` (AUTO call, no sampling params, MAX_TOKENS=4096, 5-outcome classifier);
  **T8** `harness/retriever.py` (reuse grounding-service retriever, top_k=8); **T9** `cases.py` (frozen
  `AttackCase` + closed-grammar loader); **T10** `scorer.py` (11 predicates + deviated/bypassed/INVALID +
  NOT_APPLICABLE-rejection); **T11** `stats.py` (Clopper-Pearson + Fisher + Holm); **T14** 12-case seed
  corpus `attacks/A1..E1`.
- **Final whole-branch review** = a 12-agent multi-lens adversarial Workflow. 3 Important + 2 Minor, all
  FIXED + re-reviewed clean: I-1 loader now guards every predicate's backing `expected_correct` key;
  I-2 retriever test given a real oracle; **I-3 scrubbed 3 real routable third-party IPs + a paypal
  lookalike domain (labeled malicious in a PUBLIC repo) to RFC5737 + `.example`.**

## IMMEDIATE NEXT ACTION — one hands-on step unblocks everything deferred

Every remaining Plan-1 task is gated on **Task 2 (hands-on n8n snapshot capture)**, which needs
**`vm-soc-v2-n8n` briefly powered ON**. Task 2 captures REAL n8n execution artifacts (the `retrieve`
output + the Opus `usage`) for a splunk baseline and a falcon baseline into `red-team/snapshots/`. Those
snapshots are the oracle the JS ports are validated against (they are NEVER regenerated from the port).

Then, in Plan order (all specified in the plan v2.1):

- **T4/T5/T6** — port Parse Alert, Build Opus Input, Extract Result from the deployed n8n JS to Python,
  TDD-first against the Task-2 snapshots (byte-fidelity; keep literal non-ASCII bytes).
- **T12** runner (`run_case`, the K-trial loop, wires model_client + retriever + verifier + scorer).
- **T13** report (`build_baseline_report`, per-class grouping by `case.id` prefix, Clopper-Pearson CIs).
- **T15** the actual baseline run (needs a live `ANTHROPIC_API_KEY` + a local Qdrant seeded via
  `grounding-service/scripts/ingest_attack.py`) → the committed baseline report = **Gate-3**.
- **T14b** held-out corpus in `attacks/held_out/` — MUST be authored by a DIFFERENT agent that never saw
  the hardening discussion (it is the headline for Plan-2 levers). Dispatch a blind subagent for it.

Resume the deferred tasks with `superpowers:subagent-driven-development` exactly as session 8 did
(the SDD scripts are at `.../superpowers/6.1.0/skills/subagent-driven-development/scripts/`).

## CARRY-FORWARD NOTES

- `red-team/red_team/cases.py` has a `PREDICATE_REQUIRED_FIELD` map that is a hand-maintained mirror of
  what `scorer.py` predicates read (no import, to avoid a cases<->scorer cycle). If a predicate's read key
  changes, update BOTH in lockstep.
- Pre-existing triaged Minors (non-blocking) are listed in the ledger roll-up — none block merge.
- Plan 2 (hardening) is written only AFTER the Gate-3 baseline exists (spec §9 hardens only where the
  baseline shows bypass).
