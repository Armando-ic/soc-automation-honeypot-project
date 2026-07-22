---
status: active
updated: 2026-05-26
related: [[runbooks/splunk-mcp-setup]], [[decisions/0004-mirror-mcp-to-claude-code]], [[sources/session-notes/2026-04-27-mcp-mirror-fork]], [[subprojects/2026-05-23-azure-port/runbook]]
---

# Splunk MCP

> **P2 reconfiguration pending.** The connection details below still point at the decommissioned local Splunk (`192.168.129.131`). To restore MCP queries against the Azure Splunk, update `SPLUNK_HOST` to `x.x.x.x` (public; requires home-IP-NSG access) or set up an SSH tunnel from the host to `10.0.0.5:8089`. `mcpuser` account itself was not recreated on the Azure Splunk during P2 fresh-install — re-create as needed (`splunk add user mcpuser -role admin -auth mydfir:<pw>`). Track at [[subprojects/2026-05-23-azure-port/notes]] follow-ups.

## What it is

A Model Context Protocol server that exposes Splunk to AI clients (Claude Desktop, Claude Code) as a set of tools. Lets a Claude session run searches, list indexes, and pull events directly from Splunk during a conversation.

Source: https://github.com/livehybrid/splunk-mcp (community-maintained, not Splunk-official).

## Local source location

```
F:\Claude_Code\SOC_Automation_Project\splunk-mcp-main\splunk-mcp-main\
```

(Yes, the directory name nests once due to how the GitHub zip extracts.)

## Runner

`uv` v0.11.8 at `C:\Users\Owner\.local\bin\uv`. Replaces the `poetry`-based command shown in the video tutorial — simpler and recommended by the project.

## Connection details

| | |
|---|---|
| `SPLUNK_HOST` | `192.168.129.131` |
| `SPLUNK_PORT` | `8089` (management API — **not** 8000 web UI) |
| `SPLUNK_USERNAME` | `mcpuser` |
| `SPLUNK_PASSWORD` | see [[runbooks/secrets-management]] |
| `SPLUNK_SCHEME` | `https` |
| `VERIFY_SSL` | `false` (Splunk self-signed cert in this lab) |

## Where it's installed

Mirrored across two Claude clients so investigations work from either:

| Client | Config path | Setup method |
|---|---|---|
| Claude Desktop (Microsoft Store install) | `C:\Users\Owner\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` | Edit JSON directly |
| Claude Code (VS Code) | `C:\Users\Owner\.claude.json` (project-scoped section for `F:\Claude_Code\SOC_Automation_Project`) | `claude mcp add` CLI |

The Microsoft Store sandbox path is **not** the standard `%APPDATA%\Claude\` — that path is empty for Store installs. Worth remembering when following any tutorial that assumes the standard path.

## How to use it from a Claude Code session

Say something like *"Using the splunk MCP, list available indexes"* — or any natural-language Splunk query. Claude Code will call the MCP tool. If it doesn't appear available, see [[runbooks/splunk-mcp-setup]] for the verification command and reload procedure.

## Why it's mirrored to Code (not just Desktop)

See [[decisions/0004-mirror-mcp-to-claude-code]].
