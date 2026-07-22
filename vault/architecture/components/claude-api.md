---
status: active
updated: 2026-07-22
related: [[decisions/0002-claude-api-vs-subscription]], [[architecture/components/splunk-mcp]]
---

# Claude API (in n8n)

## What it is

Programmatic access to Claude via Anthropic's API, used by the n8n workflow's "Message a model" node to perform alert triage.

## Configuration

| | |
|---|---|
| Model | `claude-opus-4-7` (the model this v1 SOC-Triage pipeline pins; the honeypot's separate triage workflow uses `claude-opus-4-8`) |
| Node type | `@n8n/n8n-nodes-langchain.anthropic` |
| Credential in n8n | `Anthropic account`. **The v1 id `VozkiMP8QqbykLLj` no longer exists** after the 2026-05-25 fresh Azure n8n install — credentials are re-bound to new ids on import (see [[architecture/components/n8n]] "Configured credentials in n8n"). |
| API key location | `SOC-Automation-Project.md` (gitignored) — see [[runbooks/secrets-management]] |

## Why API and not the Max subscription

The user pays $100/mo for Claude Max. That subscription doesn't include programmatic API access — separate billing entirely. The split:

- **API** → autonomous workflows that fire on every alert (this n8n integration)
- **Max subscription** → interactive use via Claude Desktop and Claude Code (e.g., the Splunk MCP investigations)

See [[decisions/0002-claude-api-vs-subscription]].

## Known issues to address in A1

1. System prompt sent in `assistant` role instead of `system` role (line 32 of workflow JSON)
2. `JSON.stringify` call is malformed — bare identifiers passed as the replacer arg (line 35)
3. No structured output — downstream parses `$json.content[0].text` freeform

These are tracked in [[architecture/current-state]] under "Known issues" and resolved by [[subprojects/2026-04-27-structured-outputs/README]].
