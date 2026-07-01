# Honeypot project — handoff to the next Claude instance (2026-07-01)

**You are continuing a honeypot agentic-SOC portfolio project.** This is the first session that ran in the new
`SOC-Automation-Honeypot-Project` folder. Read order:
1. **This file** (where we are + the immediate next action).
2. `infra/honeypot/session-logs/MASTER-CHECKLIST.md` — the living tracker, freshly reconciled against ground truth this session.
3. **The Phase 1 spec** `docs/superpowers/specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` (PARENT workspace, NOT a git repo).
4. `infra/honeypot/session-logs/HANDOFF.md` (Phase 0 build state) only if you need deeper Phase-0 detail.

> ⚠️ **Writing conventions the user cares about:** casual, conversational, slightly-technical tone. **No em dashes
> and no spaced-hyphen dashes** (banned); restructure with periods, commas, colons, parentheses, "and"/"so".
> Lead with action and recommendations, do not over-ask. See memory `feedback_casual_conversational_tone`,
> `feedback_prefers_hands_on_doing`, `feedback_handson_instruction_format`, `feedback_no_inline_secret_paste`.

---

## ▶ IMMEDIATE NEXT ACTION

Phase 1 (adversarial red-team) is brainstormed and the design spec is written and revised to **v2** after a
gate-1 design red-team. **Do this next:**
1. Confirm the user is happy with **spec v2** (they were reviewing it when this session ended). Make any edits they want.
2. Run **`superpowers:writing-plans`** on the approved spec to produce the implementation plan (the plan file goes in
   the PARENT `docs/superpowers/plans/`).
3. Run **gate #2 (the plan red-team)** on that plan before any code (a multi-agent adversarial review, same pattern
   we used on the spec). Only start building once the plan survives it.
4. Execute the build per spec §14: capture the real n8n snapshots and port the transform chain (system prompt,
   input builder, Falcon `map_alert`, Extract Result) **first, TDD**, then author attacks. Consider
   `superpowers:subagent-driven-development` or `executing-plans`.

---

## What this session did (2026-07-01)

1. **Set up this folder as the honeypot home** (a prior session cloned the public repo here; this session is the first working in it).
2. **Mermaid diagram redesign (DONE, committed AND pushed).** Applied the "Hybrid" colour language (trust zones plus
   an AI-brain accent) across all five diagrams: Layer-1 in both the public README and `ARCHITECTURE.md`, plus the
   four Layer-2 diagrams. Stripped IP/port clutter from node labels, grouped external SaaS, pinned each diagram to
   Mermaid's dark theme via `%%{init}%%` (fixes a real GitHub bug where a per-subgraph `style ... color:` is not
   honoured, so subgraph titles would go dark-on-dark under GitHub light theme). Then an edge-readability pass:
   `linkStyle` colours the n8n fan-out by role, dims the ingress, lights the Falcon poll arrow lime, plus a note
   that the colours are for clarity only, not good/bad. Verified by a deterministic lint + a 6-agent fidelity
   fan-out. **Commits `4009320` and `1411f72`, already pushed to `origin/ai-upgrade`.**
3. **MASTER-CHECKLIST reconciliation (DONE, committed, NOT pushed).** A 4-agent read-only Workflow verified the
   checklist against git, GitHub, Azure, and memory. Corrected: the repo is already PUBLIC (the "flip to public"
   step was stale-open), all five VMs are deallocated (the "SOC VMs are up" note was stale), the Falcon trial is 12
   days out, the v4-gcp-native loose end is resolved, and 8 commit hashes invalidated by the earlier `git
   filter-repo` secret purge were re-mapped to their post-rewrite equivalents (verified against git). **Commit `2285133`.**
4. **Credential decisions (user, recorded in checklist + memory).** The reused lab passwords are throwaway lab
   credentials and are intentionally **NOT** being rotated. The IRIS admin API key gets rotated when
   `vm-soc-v2-iris` is next allocated, not before. **There are no blocking security items.**
5. **Phase 1 scoping (via the brainstorming skill).** Locked: target = end-to-end injection against the **live
   model**; a **local** Python harness (no n8n, no Azure VMs); the **full before/after loop** with hardening scoped
   to findings. Mapped the guardrails, eval harness, and injection surface with an Explore agent. Wrote the spec,
   then ran **gate #1 (a 5-lens design red-team Workflow)** which found serious methodology flaws and produced
   **spec v2** (see below).

---

## Phase 1 status and the spec

**Spec:** `docs/superpowers/specs/2026-07-01-honeypot-phase1-adversarial-redteam-design.md` (PARENT, non-git).
Approved v1 direction; **v2** folds in the gate-1 findings (there is a v2 changelog at the top).

**What the gate-1 design red-team caught (all folded into v2), so the plan must honour these:**
- Test the REAL production prompt: load the system prompt from the generator (`build_honeypot_triage_workflow.py`
  `PROMPT` / the generated `JSON/honeypot-triage.json` `options.system`), NOT the drifted `triage-honeypot.md`.
- Offer the tool **AUTO**, not forced (forcing hides the refusal / no-tool-call path production routes to needs-human).
- Port the production **Extract Result** transform (defensive fill, `containRecommended`, `verify_body`) AND the
  Falcon **`map_alert`**, and score the exact `verify_body.result` production gates on. Two fidelity snapshots (Splunk + Falcon).
- **Retrieval is an attack surface, not a controlled variable:** run the real local retriever for poisoning cases.
- **Relative severity oracle** (catches high-to-medium under-escalation), a closed predicate grammar with hard-error
  on unknown, reframed B1 (Falcon, suppress contain), new E1 encoding class.
- **Severity floor** keys only on independent enrichment/tactic signals (never the model's echoed verdict),
  Splunk-only, caps at medium; needs the alert `source` plumbed into the `/verify` contract. Plus a **symmetric
  enrichment floor** for A2 (which today has NO deterministic check).
- **Honest stats:** tiered K (5 explore / >=50 headline), reported CIs, no bare-zero claims, a **held-out corpus
  authored by a different agent**, per-class reporting, significance tests, pinned temperature. Align `eval_runner`
  so `eval.py` runs the full 10-check path.

**Review gates (spec §15):** gate 1 (design) DONE. **Gate 2 (plan red-team) and gate 3 (build + report red-team)
are still pending.** Do not skip them.

---

## Git state (IMPORTANT)

- Branch **`ai-upgrade`**, upstream **`origin/ai-upgrade`** (`github.com/Armando-ic/soc-automation-honeypot-project`, **PUBLIC**).
- **Unpushed commits:** `2285133` (checklist reconcile) plus the commit that carries THIS handoff file. The two
  diagram commits (`4009320`, `1411f72`) are already pushed. **Decide the push with the user** (public repo).
- Working tree clean apart from the handoff commit.
- The Phase 1 **spec v2** and all **memory** updates are saved to disk in non-git locations (PARENT
  `docs/superpowers/`, and `~/.claude/.../memory/`), so they are safe but not in git.

## Live / infra state (NOT in git)

- **All five Azure VMs are DEALLOCATED** (verified 2026-07-01): `vm-soc-v2-n8n`, `vm-soc-v2-splunk`,
  `vm-soc-v2-iris`, `vm-soc-v2-win`, `vm-honeypot-win`. No organic-capture window is open.
- **Phase 1 does NOT need the Azure VMs.** The local harness needs only a local Qdrant plus the bge-small embedder,
  runnable via the existing `grounding-service` docker compose, and the Claude API.
- **Falcon trial expires 2026-07-13** (12 days as of 2026-07-01). Not needed for Phase 1.
- The **Claude API key** for the harness is in the gitignored creds file (`Personal/` / `SOC-Automation-Project.md`).
  Load it from there, never inline.

## Conventions (do not violate)

- **Never `git add -A`** — add exact paths. Keep `Personal/`, `.playwright-mcp/`, `__pycache__/` out.
- **No inline secret paste**; the user loads secrets from the gitignored creds file on a local machine.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Specs and plans live in the PARENT `docs/superpowers/` (NOT a git repo). The repo holds implementation artifacts.
- The public repo's default branch is intentionally `ai-upgrade` (no rename to `main`).

## Reusable pattern worth keeping

The highest-value move this session was running a **multi-agent adversarial verification Workflow at each artifact
boundary**: diagram fidelity, checklist-vs-ground-truth, and especially the **design red-team** which caught spec
flaws (a drifted prompt, a self-defeating hardening check, indefensible K=5 statistics) that would otherwise have
shipped a misleading public report. Reuse it for the plan (gate 2) and the build (gate 3).
