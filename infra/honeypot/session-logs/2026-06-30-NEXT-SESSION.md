# Honeypot project — handoff to the next Claude instance (2026-06-30, session 2)

**You are continuing a honeypot agentic-SOC portfolio project.** This file supersedes the earlier
2026-06-30 handoff (preserved in git history at commit `99f3e39`). Read order:
1. **This file** (where we are + the immediate next action).
2. `infra/honeypot/session-logs/MASTER-CHECKLIST.md` — the living progress tracker. This is the canonical state; it
   shows every phase, what's done, and what's left. Read it second.
3. `infra/honeypot/session-logs/HANDOFF.md` (🟢 0D-2 block) — deeper build state for Phase 0.
4. `infra/honeypot/ARCHITECTURE.md` — the plain-language walkthrough of the whole system.

> ⚠️ **Writing conventions (the user cares about these):** write in a **casual, conversational,
> slightly-technical tone** (explaining to a sharp peer, not corporate). **No em dashes and no spaced-hyphen
> dashes** (the user banned them); restructure with periods, commas, colons, parentheses, or "and"/"so".
> Prefer full sentences over telegraphic shorthand or `→` arrows. Lead with action and recommendations,
> don't over-ask. See memory `feedback_casual_conversational_tone`, `feedback_prefers_hands_on_doing`,
> `feedback_handson_instruction_format`.

---

## ▶ IMMEDIATE NEXT ACTION — commit sub-project C ✅ DONE (session 3)

> **UPDATE (session 3, 2026-06-30):** Done. C was committed as `84453f2` (the 5 files below), and the master
> checklist was closed out in `53e5173` (final C box ticked, "Where we are" pointer moved to D). The three
> throwaway `*-NOTED.json` exports were deleted, this handoff doc was committed, and `ai-upgrade` was pushed to
> `honeypot/ai-upgrade`. The original instructions are kept below for the record. **Next deliverable is D**
> (organize the repo for public). Confirm with the user before diving in.

All of sub-project **C** (organize the 3 n8n workflows for presentation) is finished and verified. The work
is saved to disk but **not committed**. Your first job is to commit it. Five files, on branch `ai-upgrade`:

- `infra/honeypot/build_falcon_poller_workflow.py` + `JSON/falcon-alert-poller.json`
- `infra/honeypot/build_falcon_contain_workflow.py` + `JSON/falcon-contain.json`
- `infra/honeypot/session-logs/MASTER-CHECKLIST.md`

**Do NOT `git add -A`.** Add exactly those five paths. Keep these untracked files OUT of the commit:
`.playwright-mcp/`, `infra/honeypot/__pycache__/`, and the three throwaway exports
`JSON/falcon-alert-poller-NOTED.json`, `JSON/falcon-contain-NOTED.json`, `JSON/honeypot-triage-NOTED.json`
(those are the user's polluted n8n exports — real cred IDs, `instanceId`, the poller one is even missing the
`IF has_new` node. The generators are the source of truth, not those.)

Suggested commit (multi `-m`, ends with the required trailer):
```
git add infra/honeypot/build_falcon_poller_workflow.py JSON/falcon-alert-poller.json infra/honeypot/build_falcon_contain_workflow.py JSON/falcon-contain.json infra/honeypot/session-logs/MASTER-CHECKLIST.md
git commit \
  -m "docs(honeypot): poller + contain presentation polish, voice + accuracy pass" \
  -m "Fold the hand-tuned n8n layouts back into both generators via POS maps (sections recolored near-black). Re-added the poller IF has_new node that was deleted in the user's export, at [940,0]." \
  -m "Rewrite all poller + contain sticky cards in the casual full-sentence voice (no em dashes, no arrow shorthand)." \
  -m "A 12-agent doc-accuracy fan-out tightened several imprecisions: poller identical->same pipeline, exactly-once->bounded once, restored the per-run cap, ack-for-every-one->until-first-failure; contain verifies->reads-back-status, never-strands->always-attempts-self-lift, contained-status read reframed as observed-not-gated. No hard bugs found." \
  -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```
After this commit, **C is fully done** and the checklist's last C box can be checked.

**Then — push decision (ask the user):** branch `ai-upgrade` tracks `honeypot/ai-upgrade`. As of the pause it
is **2 commits ahead, unpushed** (`f3e368f` triage polish + the C-closing commit you're about to make). Ask
whether to push now or hold.

---

## What this session did (2026-06-30, session 2)

This whole session was **pre-Phase-1 portfolio prep, sub-project C** (organize the 3 n8n workflows so they
read like the template gallery: doc strip + section group-boxes + clean prose). Sequence of what happened:

1. **honeypot-triage** — folded the user's hand-tuned canvas (layout, colors, the rewritten "What it does"
   card) back into `build_honeypot_triage_workflow.py` via an authoritative `POS` map; regenerated the clean
   public-ready JSON. Ran a 5-agent doc-accuracy fan-out → fixed three real errors (Iris **alert** not case;
   the IOC gate skips only when there's no source IP; Opus is *instructed* to stay grounded while the verifier
   *enforces* it). **COMMITTED as `f3e368f`.**
2. **falcon-alert-poller + falcon-contain** — same playbook: folded the user's two hand-tuned exports back
   into their generators (`POS` maps, near-black sections), voice-passed every card, ran a 12-agent
   doc-accuracy fan-out, tightened ~7 imprecisions. Re-added the poller `IF has_new` node (the user's export
   had accidentally deleted it). **Regenerated, verified clean, NOT yet committed** (that's your job above).

Reusable tool worth knowing: the **doc-accuracy fan-out** is a `Workflow` that spawns one agent per sticky
card to fact-check its claims against the actual code (the generators + `grounding-service/` + `triage-verifier/`).
It caught the "Iris case" bug and the contain "verifies vs observes" overstatement. Reuse it for any new
public-facing docs (README, ARCHITECTURE) before they ship.

---

## Where the project is (summary — full detail in MASTER-CHECKLIST.md)
- **Phase 0** ✅ shipped, autonomous loop live.
- **Pre-Phase-1 portfolio prep** 🟡: A+B (docs) ✅ · **C (workflow organization) ✅ once you commit** ·
  footage (trial-gated) = decision made to **let it ride** · **D (organize repo for public) ⬜ = the next
  deliverable.**
- **Portfolio VIDEO** ⏸️ deferred by the user to **after all main phases** (Phases 1-5) are built.
- **Phases 1-5** are roadmap-only; each gets brainstorm → spec → plan before any building.

**Likely next work after the commit:** sub-project **D** (secret-scrub pass, repo structure, public README
with the ARCHITECTURE diagram embedded). Confirm direction with the user before diving in — they may want to
start Phase 1 planning instead.

---

## Live state the fresh instance MUST know (NOT in git)
- **Falcon trial expires 2026-07-13** (~13 days from the 06-30 baseline). Anything needing the live Falcon API
  must happen before then. Footage was intentionally **not** captured now (user will re-establish Falcon access
  at video time, after all phases).
- **SOC VMs** (`vm-soc-v2-n8n`, `vm-soc-v2-splunk`, RG `rg-soc-v2-azure-central-us`) auto-deallocate ~23:00 ET.
  If a session leaves them up, deallocate when done: `az vm deallocate -g rg-soc-v2-azure-central-us -n <vm>`.
- **`falcon-alert-poller` Schedule Trigger is ACTIVE** (autonomous 15-min poll); `grounding-service` runs the
  #10-hardened image. The polished generator JSONs are presentation artifacts — they are NOT the live workflow;
  do not import them over the running ones without intent.

## Conventions (do not violate)
- **Never `git add -A`** — add exact paths; keep `Personal/`, `.playwright-mcp/`, `__pycache__/`, and the
  `*-NOTED.json` throwaway exports out.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **No inline secret paste** — have the USER load secrets from gitignored `Personal/honeypot-vm-creds.txt` /
  `SOC-Automation-Project.md`; secret-bearing commands run on a LOCAL machine, never the honeypot.
- **The generators are the source of truth** for the workflow JSONs. When the user hand-tunes a canvas in n8n
  and exports, fold the layout (positions/sizes/colors) back into the generator's `POS` map + `sticky(...)`
  block and regenerate — don't commit the raw export (it carries real cred IDs + `instanceId`). Tip for the
  user: import into a **fresh empty n8n tab** to avoid `1`-suffixed duplicate node names.
- Hands-on blocks: lead with a **"Where:"** machine+access header, numbered commands, lists not prose.

## Git / push state
- Branch **`ai-upgrade`**, upstream **`honeypot/ai-upgrade`** (`github.com/Armando-ic/soc-automation-honeypot-project`).
- Session 2 committed `f3e368f` (triage polish). Session 3 then committed `84453f2` (poller + contain),
  `53e5173` (checklist closure), and this handoff doc, deleted the throwaway `*-NOTED.json` exports, and
  **pushed `ai-upgrade` to `honeypot/ai-upgrade`** (branch now in sync with the remote).
- Still untracked and out of git on purpose: `.playwright-mcp/` and `infra/honeypot/__pycache__/` (both are
  natural `.gitignore` candidates to fold into the sub-project D repo-tidy pass).
- Strategy/spec/plan docs live in the PARENT workspace `docs/superpowers/` (NOT a git repo). `MASTER-CHECKLIST.md`,
  `ARCHITECTURE.md`, and the workflow generators/JSONs ARE in this repo.
