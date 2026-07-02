# Honeypot Phase 1 build — handoff to the next Claude instance (2026-07-01, session 7)

**You are mid-build on the Phase 1 red-team harness.** This handoff supersedes the session-6 handoff for
"what to do next," but that file is still the best deep background. Read order:

1. **This file** (what session 7 did + exact resume state + immediate next action).
2. **The ledger** `infra/honeypot/session-logs/../../../.superpowers/sdd/progress.md` (repo-root
   `.superpowers/sdd/progress.md`) — the durable recovery map. Trust it and `git log` over any recollection.
3. **Plan v2.1** `docs/superpowers/plans/2026-07-01-honeypot-phase1-redteam-harness-baseline.md`
   (PARENT workspace `f:\Claude_Code\Skills-Learning\docs\...`, NOT a git repo). This is what you build.
   Read its top "v2 changelog" + "v2.1 changelog" notes first.
4. **Spec v2.1** `docs/superpowers/specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` (PARENT).
5. `infra/honeypot/session-logs/2026-07-01-NEXT-SESSION.md` (session-6 handoff) for Phase-1 background,
   conventions, and infra/VM state.

> Writing conventions the user cares about: casual, conversational, slightly-technical. No em dashes and no
> spaced-hyphen dashes in prose (restructure with periods, commas, colons, parentheses). One exception: code
> that must byte-match production keeps its literal em dash / bullet / check characters. Lead with action and
> recommendations, do not over-ask. Prefer USER hands-on for anything on the honeypot/VMs. No inline secret
> paste. Memory keys: feedback_casual_conversational_tone, feedback_prefers_hands_on_doing,
> feedback_handson_instruction_format, feedback_no_inline_secret_paste.

---

## IMMEDIATE NEXT ACTION

Resume the build via `superpowers:subagent-driven-development` (fresh implementer + task reviewer per task).
The controller loop, ledger, and task briefs already exist. Do this:

1. **Finish Task 1 (it was interrupted mid-flight, nothing committed).** Re-dispatch a Task-1 implementer to
   COMPLETE, not recreate: the source files (`red-team/pyproject.toml`, `red-team/red_team/`,
   `red-team/tests/`) are already on disk (untracked); the venv already has `triage-verifier` and
   `grounding-service` installed editable. Remaining: `pip install -e ".[dev]"` for red-team, ensure
   `README.md` + `.gitignore` exist per the brief, run `.venv/Scripts/python -m pytest tests/test_scaffold.py -v`
   green, then commit exact paths + trailer. Review BASE = `b6b263e`. (Task-1 brief already extracted at
   `.superpowers/sdd/task-1-brief.md`.)
2. **Continue in order: Task 3, 7, 8, 9, 10, 11, 14.** One implementer at a time. For each: run the skill's
   `scripts/task-brief PLAN N` -> dispatch implementer with the brief path -> on DONE run
   `scripts/review-package BASE HEAD` -> dispatch task reviewer with the printed path -> fix-loop on
   Critical/Important -> append `Task N: complete (commits base7..head7, review clean)` to the ledger.
3. **Then the final whole-branch review** on the most capable model (opus), using
   `scripts/review-package <merge-base> HEAD`.
4. **Deferred to a follow-on run (NOT this build):** Task 2 (hands-on snapshot capture, needs
   `vm-soc-v2-n8n` briefly ON, user-driven) and the snapshot/live-dependent Tasks 4, 5, 6, 12, 13, 15.

SDD scripts live at:
`C:\Users\Owner\.claude\plugins\cache\claude-plugins-official\superpowers\6.1.0\skills\subagent-driven-development\scripts\` (task-brief, review-package, sdd-workspace).

---

## What session 7 did

1. **Focused re-gate of Plan v2** (the v2 had never been re-reviewed after gate-2). Ran a 10-agent Workflow:
   5 review dimensions (model-call fidelity, reused-imports, port-sources, tool-schema-loading,
   scoring/consistency), adversarial verify of each finding against the repo, plus a completeness sweep.
   Also invoked the `claude-api` skill and confirmed the model-call rewrite is correct
   (temperature/top_p/top_k 400 on Opus 4.8; max_tokens required; omitting thinking/effort/tool_choice matches
   the deployed langchain-anthropic node; refusal/max_tokens are valid stop_reasons).
2. **Re-gate verdict: plan is buildable; 1 blocker + 3 minors, all now FIXED in the plan (-> v2.1):**
   - BLOCKER (fixed): Task 3 `load_tool_def` selected the tool node by `parameters.name`, but the deployed
     toolCode node's identity is the TOP-LEVEL `node["name"]` (no `parameters.name` key), so the loop raised
     LookupError and Task 3's test could never pass. Selector now uses `node.get("name")`. The corrected
     oracle was verified live: deployed `options.system == generator.PROMPT` and deployed
     `inputSchema == generator.SCHEMA` both hold today.
   - MINOR (fixed): dropped the unused `HIGH_SEVERITY_TACTICS` import (lines 32 + Task 10 Consumes).
   - MINOR (fixed): documented that `injected_ioc_present`'s guard maps to an always-on check, so its
     NOT_APPLICABLE-rejection is a harmless no-op.
   - MINOR (fixed): made Task 13's class-code grouping (`case.id` prefix) and OPEN-derivation explicit.
   - Everything else verified SOUND: all 7 reused imports + signatures, verify() returning .passed/.results,
     every JS port line-range + the `if (!toolCall) throw` (refusal-can't-bypass foundation), top_k=8,
     PREDICATE_GUARD keys == KNOWN_PREDICATES, cross-task type consistency, K-loop, Task 11 stats formulas.
3. **Started the build** via subagent-driven-development for the 8 snapshot-independent tasks
   (1, 3, 7, 8, 9, 10, 11, 14). Task 1 implementer got interrupted for a context-budget pause (see resume
   state). No commits landed.

## Git + files state (verified at pause)

- Branch **ai-upgrade**, HEAD **b6b263e**, in sync with `origin/ai-upgrade` (PUBLIC repo). Nothing committed
  this session. Local commits only; do NOT push without user OK.
- Working tree: `red-team/` is UNTRACKED (partial scaffold from the interrupted Task 1); the venv under
  `red-team/.venv/` has triage-verifier + grounding-service installed. `infra/honeypot/session-logs/2026-07-01-NEXT-SESSION.md`
  is still modified (session-6 handoff, uncommitted, unrelated). `.superpowers/` is git-ignored scratch
  (holds the ledger + task briefs).
- Plan v2.1 and Spec v2.1 edits live in the PARENT `docs/superpowers/` (non-git) — safe, not in the repo.
- Never `git add -A`; add exact `red-team/...` paths per each task's brief. Do not stage the session-6
  handoff or `.superpowers/`.

## Conventions (do not violate)

- Build on `ai-upgrade`, local commits only, no push without user OK.
- Conventional commits, `(honeypot)` scope, and EVERY commit ends with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Windows venv path `.venv/Scripts/python`; run pytest from inside `red-team/`; editable installs in
  dependency order (triage-verifier, then grounding-service, then `.[dev]`), NOT declared in pyproject.
- When touching Claude/Anthropic model params, the plan is already validated against the `claude-api` skill —
  build Task 7 as written (send only model+system+tools+max_tokens+messages).
- Model choices used this session: implementers + task reviewers on `sonnet`; final whole-branch review on
  `opus`. Use the cheapest tier that fits per the SDD skill's Model Selection.

## Memory

Project memory note (`project_honeypot_agentic_soc`) should get a session-7 line: re-gate done, plan is v2.1
(1 blocker + 3 minors fixed), SDD build of the 8 snapshot-independent tasks started, Task 1 interrupted
mid-flight (uncommitted), resume per the ledger. (Not yet written at pause — do this on resume.)
