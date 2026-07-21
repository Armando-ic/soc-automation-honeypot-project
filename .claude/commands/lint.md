---
description: Documentation-consistency lint (reports-only) for the honeypot repo. `/lint` runs both tiers; `/lint fast` runs the deterministic tier only; `/lint fix` applies fixes on explicit direction.
---

You are running the repo's documentation linter. It is REPORTS-ONLY unless the argument is `fix`. Never modify a linted file except under `fix`, and even then only after confirming each change. This is NOT the secret scrub gate and NOT the code toolchain (black/isort/mypy) — do not do those here.

Argument: `$ARGUMENTS` (one of empty, `fast`, or `fix`).

## Tier 1 — deterministic (always run)

Run `python tools/doc_lint.py` from the repo root and capture its output. These findings are CERTAIN (broken links, relative-date phrases, vault structural conformance). Report them first, grouped by check, each with its `file:line`.

If the argument is `fast`, STOP after Tier 1: print the report, append the journal line (see below with `contradictions:- stale:-`), and end.

## Tier 2 — semantic (only when the argument is empty)

Compute two ground-truth inputs first (Workflows cannot read the clock or the filesystem):
1. `today` = the current date (from the environment / `date +%Y-%m-%d`).
2. `newest_handoff` = the lexically-largest filename in `infra/honeypot/session-logs/` matching `*HANDOFF.md` (dated names sort correctly).

Then launch a Workflow that fans out over the in-scope doc zones (top-level, `infra/honeypot`, `grounding-service`+`triage-verifier`, `vault`) and runs, reports-only:

- **Cross-doc contradictions:** finders extract the drift-prone atomic claims (numeric thresholds, network/IP-handling rules, port lists, state/HEAD pointers, DONE/NOT-built status, config values, key dates), cross-compare for genuine conflicts across DIFFERENT docs, then a skeptic-per-finding pass classifies each candidate (real contradiction / superseded-with-note / same-fact-different-words), then a completeness critic asks what pairs were missed. Report each survivor with both `file` locations, the conflicting quotes, and a confidence.
- **Stale / passed claims:** pass `today` and `newest_handoff` into the finders. Flag (a) deadlines earlier than `today` that are framed as still-pending/blocking, and (b) any "latest handoff" / "where we are" pointer that does not reference `newest_handoff` or the real current phase.

Use the project's standard finder → skeptic → critic Workflow shape (see the Workflow tool's review pattern). Keep the fan-out reports-only; the Workflow returns structured findings, it does not edit files.

## Output + journal

Print one consolidated report: Tier-1 findings first (certain), Tier-2 second (with confidence + spanned docs). State "0 findings" explicitly per check when clean. Then append ONE line to `lint-log.md`:
`<today> | <mode> | links:<n> dates:<n> vault:<n> contradictions:<n> stale:<n>` (use `-` for tiers not run).

## `fix` mode

Only when the argument is `fix`: git is the snapshot (the tree is versioned). Propose the fixes, get the user's go, apply them, then RE-RUN `python tools/doc_lint.py` to confirm mechanical fixes cleared. For any semantic (Tier-2) fix, verify against ground truth (the code, `newest_handoff`, the actual state) BEFORE applying. Never auto-fix without confirmation.
