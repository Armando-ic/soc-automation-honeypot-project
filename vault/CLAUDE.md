# SOC Automation Project — Vault Schema

You are working in the documentation vault for an n8n-based SOC automation pipeline. This file tells you how the vault is organized, what conventions to follow, and what tools you have available. Read it first whenever you open this project.

## What this project is

A SOC (Security Operations Center) automation lab built on:

- **Splunk** as the SIEM (10.0.0.5)
- **n8n** as the SOAR / workflow engine (10.0.0.6)
- **DFIR-Iris** as case management / ticketing (10.0.0.7)
- **Claude API** for AI triage inside the n8n workflow
- **Claude Desktop / Claude Code** for interactive investigation, talking to Splunk via MCP
- **DFIR-Iris native review** for the human-approval gate (Slack was removed per ADR 0007)
- **VirusTotal + AbuseIPDB** for IOC enrichment

Data flow today: Splunk alert → n8n webhook → Claude triage with enrichment tools → DFIR-Iris alert (analyst reviews and escalates natively, per ADR 0007).

The user is expanding this past the original tutorial into a more sophisticated platform. Work happens in **sub-projects**, each with its own folder, spec, and plan.

## Tools available to you (Claude Code in this project)

You have an MCP server named `splunk` configured at local scope, connecting to Splunk at `192.168.129.131:8089` (management API) as `mcpuser`. Use it for live SIEM queries when investigating alerts, validating detections, or sanity-checking designs against real data. **If a question can be answered by querying Splunk, query Splunk — don't speculate from memory or training data.**

If the MCP appears not to be connected, see [[runbooks/splunk-mcp-setup]].

## Where to find what

| You need... | Look in... |
|---|---|
| Current active sub-project | `subprojects/` (latest dated folder) |
| As-is system architecture | `architecture/current-state.md` |
| Component details | `architecture/components/<component>.md` |
| Why a non-obvious choice was made | `decisions/` (numbered ADRs) |
| How to do an operation | `runbooks/` |
| Per-MITRE-technique detection content | `detections/` (one page per T-id; `_template.md` to add new) |
| Recent activity history | `log.md` (tail it) |
| Catalog of every wiki page | `index.md` |
| Original screenshots, JSON exports | `../Photos/`, `../JSON/` at project root |
| Past session notes | `sources/session-notes/` |

## Sub-project conventions

- Folder name: `subprojects/YYYY-MM-DD-<short-topic>/`
- Required files inside each sub-project folder:
  - `README.md` — fresh-instance entry point ("read these in this order")
  - `spec.md` — design (what + why) approved before implementation
  - `plan.md` — implementation plan (how + tasks) created by the writing-plans skill
  - `runbook.md` — how to operate the result, written during/after build
  - `notes.md` — working notes, gotchas, learnings
- A sub-project is "done" when its runbook covers the live system and notes captures lessons learned

## Decision records (ADRs)

- Numbered sequentially starting at 0001
- Filename: `decisions/NNNN-short-slug.md`
- **Immutable once written.** If a decision is reversed, write a new ADR that supersedes the old one and links to it; never edit the original.
- Required sections: Status, Context, Decision, Consequences

## The log

`log.md` is append-only. Add a one-line entry whenever you finish meaningful work:

```
YYYY-MM-DD — short description; see [[link to relevant file]]
```

For events reconstructed after the fact, prefix with `[backfilled]`.

## Linking and frontmatter

- Use `[[wiki-style links]]` for cross-references between vault files (Obsidian renders them)
- Use relative markdown links for files outside the vault (e.g., `[workflow JSON](../../JSON/SOC-Automation-Project-Workflow.json)`)
- Frontmatter on every wiki page (not on `log.md`):

```yaml
---
status: draft | active | superseded | archived
updated: YYYY-MM-DD
related: [[other-page]], [[another-page]]
---
```

## What NOT to do

- **Don't put secrets in `vault/`.** Secrets live in `../SOC-Automation-Project.md` at project root, which is gitignored. See [[runbooks/secrets-management]].
- **Don't edit historical entries** in `log.md` or `decisions/`. Append, supersede, or write a new file.
- **Don't create files outside the structures above** without updating `index.md`.
- **Don't duplicate information.** If the workflow JSON is the source of truth for what nodes exist, link to it — don't transcribe it.
- **Don't write a sub-project spec without going through the brainstorming skill first.** The skill exists to catch underspecified work before it wastes time.

## Working with the user

The user is building this as a portfolio project and learning vehicle. They value:

- Honest critique over validation
- Granular planning over hand-waving
- Splitting work into shippable units over big-bang efforts
- Knowing *why* something is the way it is

When in doubt, slow down and ask. The vault exists so future-you (or another fresh instance) doesn't have to.
