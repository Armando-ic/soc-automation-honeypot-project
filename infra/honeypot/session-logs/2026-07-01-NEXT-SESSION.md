# Honeypot project — handoff to the next Claude instance (2026-07-01, session 6)

> ⛔ **SUPERSEDED (2026-07-05, session 16).** This is a stale point-in-time handoff from session 6; its "immediate
> next action" (build Plan 1) was completed and PUBLISHED long ago, and Plan 2 hardening is now also DONE + PUBLISHED.
> **Current read-first:** `infra/honeypot/session-logs/2026-07-05-SESSION16-PLAN2-COMPLETE-PUBLISHED-HANDOFF.md` +
> `MASTER-CHECKLIST.md` ("Where we are right now"). Kept only for historical context.

**You are continuing a honeypot agentic-SOC portfolio project.** This handoff supersedes the earlier
2026-07-01 handoff (git history preserves that one). Read order:
1. **This file** (where we are + the immediate next action).
2. `infra/honeypot/session-logs/MASTER-CHECKLIST.md` — the living tracker.
3. **The Phase 1 spec (v2.1)** `docs/superpowers/specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` (PARENT workspace, NOT a git repo).
4. **The Phase 1 Plan 1 (v2)** `docs/superpowers/plans/2026-07-01-honeypot-phase1-redteam-harness-baseline.md` (PARENT, NOT git). This is what you build.
5. `infra/honeypot/session-logs/HANDOFF.md` (Phase-0 build state) only if you need deeper Phase-0 detail.

> ⚠️ **Writing conventions the user cares about:** casual, conversational, slightly-technical tone. **No em dashes
> and no spaced-hyphen dashes** in prose/docs (restructure with periods, commas, colons, parentheses). One exception:
> code that must byte-match production keeps its literal `—`/`•`/`✅` characters. Lead with action and
> recommendations, do not over-ask. Memory: `feedback_casual_conversational_tone`, `feedback_prefers_hands_on_doing`,
> `feedback_handson_instruction_format`, `feedback_no_inline_secret_paste`.

---

## ▶ IMMEDIATE NEXT ACTION

Phase 1 is spec'd (v2.1), planned (Plan 1 v2), and both artifacts survived their adversarial gates. **Do this next:**

1. **(Optional but cheap) Focused re-gate of the Plan v2 fixes.** Plan 1 was revised AFTER gate-2; the revised v2 has
   NOT itself been re-reviewed. If you want belt-and-suspenders, run a small Workflow re-checking only the fixed
   items (temperature removed / max_tokens / refusal-cannot-bypass / run_meta usage / top_k=8 / __main__ guard /
   PREDICATE_GUARD / tool-schema load / K-loop). If you trust the fixes, skip straight to build.
2. **BUILD Plan 1** via `superpowers:subagent-driven-development` (fresh implementer + reviewer per task). Start at
   **Task 1 (scaffold `red-team/`)**. The plan is fully TDD with exact code and commit messages per task.
3. **Task 2 is HANDS-ON (user):** capturing the two real n8n execution snapshots (Splunk + Falcon) needs
   `vm-soc-v2-n8n` briefly ON (it is deallocated). Prefer exporting an EXISTING Phase-0 execution from the n8n
   history. The snapshot MUST include `retrieve_output` (the candidate-technique menu) and `opus_usage` (token
   counts), Tasks 5 and 6 parity tests depend on them. Tasks 9-11 (scorer/stats/cases) have no snapshot dependency
   and can proceed while the VM decision is pending.
4. **Gate-3 (build + report red-team)** happens during/after implementation (spec §15). Do not skip it.

---

## What this session did (2026-07-01, session 6)

1. **Pushed** the 2 previously-unpushed commits (`2285133` checklist-reconcile + `b6b263e` prior handoff) to public
   `origin/ai-upgrade` (user OK).
2. **Spec-v2 codebase-fidelity verification (7-agent Workflow).** Fact-checked every code claim in the Phase-1 spec
   vs the real repo. The design was faithful, but 2 factual errors were caught and fixed in **spec v2.1**: the
   verifier runs **10 checks not 8** (§1), and the §6 Falcon sub-field list omitted **`severity_name`** (the field
   B1 targets). Also labeled Falcon under-escalation structurally OPEN (like A2) and added a **§16 "resolve in
   writing-plans" checklist** of ~10 implementation under-specs.
3. **Wrote Plan 1** (`superpowers:writing-plans`), 15 tasks, harness-through-committed-baseline-report. Key design:
   **reuse** `grounding_service.falcon.map_alert`, the verifier, the retriever, and the embedder as imports; **port**
   only Parse Alert + Build Opus Input + Extract Result (JS→Python) TDD-first, validated against **real n8n
   snapshots** (never regenerated from the port). Hardening is deferred to **Plan 2** (spec §9 hardens only where the
   baseline shows bypass).
4. **Gate-2 plan red-team (5-lens Workflow)** = `ready_to_build:false`, 4 blocking + 8 major, verified against the
   **claude-api** skill and the repo. **Applied every fix → Plan v2** (a "v2 changelog (post gate-2)" note is at the
   top of the plan). The most important catches (all real):
   - **`temperature` 400s on Opus 4.8** (sampling params are removed). The harness sends NO `temperature`/`top_p`/
     `top_k`/`thinking`/`effort`, matching the deployed n8n langchain-anthropic node (which sets only
     `options.system`). There is no temperature to pin; stochasticity is characterized by the K-trial CIs.
   - **`max_tokens` is required** → a concrete `MAX_TOKENS` constant; `stop_reason == "max_tokens"` scored INVALID.
   - **A refusal / no-tool-call can never be a bypass.** Production Extract Result THROWS on no tool call, before any
     `verify_body` or gate exists → routes to needs-human, `bypassed=False` by construction. Only a **PARTIAL** tool
     call (tool fired, fields omitted) reaches the gate via the defensive fill and can bypass.
   - **Extract Result parity must thread the captured Opus `usage`** or `run_meta.tokens_in/out` mismatch fails the
     byte-match even on a perfect port.
   - Major: `top_k=8` (not 6) to match production; snapshot captures the retrieve output + Opus usage; a `__main__`
     guard is added to the generator BEFORE Task 3 imports it (it currently writes the tracked JSON on import); a
     `PREDICATE_GUARD` map makes the NOT_APPLICABLE-rejection rule implementable; the tool schema is loaded from the
     generated JSON and checked against the generator `SCHEMA`; the K-loop is explicit + tested at k>1; the drifted
     `triage-verifier/prompts/triage-honeypot.md` gets a non-canonical banner.

---

## Git state

- Branch **`ai-upgrade`**, upstream **`origin/ai-upgrade`** (`github.com/Armando-ic/soc-automation-honeypot-project`, **PUBLIC**), in sync at session start.
- **This session's only repo change is THIS handoff file** (and, if you commit it, the MASTER-CHECKLIST update). The
  spec (v2.1) and Plan 1 (v2) live in the PARENT `docs/superpowers/` (non-git). Memory is in `~/.claude/.../memory/`.
- **Open decision for the user:** whether to commit + push this handoff (and a MASTER-CHECKLIST tick) to the public
  repo now, or leave it local. Nothing is committed yet this turn.

## Live / infra state (NOT in git)

- **All five Azure VMs are DEALLOCATED.** Phase 1's harness needs only a local Qdrant + the bge-small embedder
  (runnable via the existing `grounding-service` docker compose, no Azure) plus the Claude API. **Exception: Plan 1
  Task 2 (snapshot capture) needs `vm-soc-v2-n8n` briefly ON.**
- **Falcon trial expires 2026-07-13.** Not needed for Phase 1.
- The **Claude API key** for the live baseline (Plan 1 Task 15) is in the gitignored creds file. Load it into
  `ANTHROPIC_API_KEY` from a local machine, never inline.

## Conventions (do not violate)

- **Never `git add -A`** — add exact paths. Keep `Personal/`, `.env`, `__pycache__/` out.
- **No inline secret paste**; the user loads secrets from the gitignored creds file on a local machine.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Conventional commits,
  `(honeypot)` scope.
- Specs and plans live in the PARENT `docs/superpowers/` (NOT a git repo). The repo holds implementation artifacts
  (the `red-team/` package Plan 1 builds is a new sibling of `triage-verifier/` and `grounding-service/`).
- The public repo's default branch is intentionally `ai-upgrade` (no rename to `main`).
- **Whenever you touch Claude/Anthropic model params, read the `claude-api` skill first** — it caught the
  temperature-400 that would have broken every live call this session.

## Reusable pattern worth keeping

Run a **multi-agent adversarial Workflow at every artifact boundary**: it caught 2 factual spec errors at gate-1,
and at gate-2 caught a `temperature` parameter that 400s on Opus 4.8 (would have failed every baseline call), a
fabricated refusal-bypass scoring path, and a token-parity test bug. Reuse it for gate-3 (build + report).
