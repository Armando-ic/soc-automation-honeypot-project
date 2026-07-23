---
status: active
updated: 2026-04-27
related: [[architecture/components/splunk-mcp]], [[decisions/0004-mirror-mcp-to-claude-code]], [[sources/session-notes/2026-04-27-mcp-mirror-fork]]
---

# Splunk MCP Setup

How to install and verify the Splunk MCP server for both Claude Desktop and Claude Code on Windows.

> **P2 reconfiguration pending (post-Azure port).** The `SPLUNK_HOST` value used below (`192.168.129.131`) is the **v1-era local-VMware IP**, decommissioned during the P2 Azure port. Splunk now runs on Azure at `10.0.0.5:8089`, but this MCP has **not yet been repointed** and the `mcpuser` account was not recreated on the Azure Splunk. When standing up a fresh instance against the Azure Splunk, substitute `10.0.0.5` for `192.168.129.131` in the `SPLUNK_HOST` values below and re-create `mcpuser` first. See [[architecture/components/splunk-mcp]] and [[architecture/current-state]] known-issue #7.

## Prerequisites

- Splunk reachable from the host machine on port 8089 (the management API, **not** 8000 web UI)
- A Splunk user account for the MCP — currently `mcpuser`, admin role (downgrade tracked)
- Python 3.13+ installed and on PATH
- `uv` installed (`pip install uv` or download from astral-sh/uv releases)
- The `splunk-mcp` source extracted at `F:\Claude_Code\SOC_Automation_Project\splunk-mcp-main\splunk-mcp-main\`
- One-time: `cd` into the source dir and run `uv sync` to install dependencies

## Sandbox path gotcha (Microsoft Store installs)

If Claude Desktop was installed from the Microsoft Store, its config is **not** at `%APPDATA%\Claude\claude_desktop_config.json`. That path is empty.

The real path is:

```
C:\Users\Owner\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json
```

Any tutorial that says "edit `%APPDATA%\Claude\...`" is assuming the non-Store install. Open the Store config path manually.

## Claude Desktop setup

Edit the config file (path above) to add:

```json
{
  "mcpServers": {
    "splunk": {
      "command": "uv",
      "args": [
        "--directory",
        "F:\\Claude_Code\\SOC_Automation_Project\\splunk-mcp-main\\splunk-mcp-main",
        "run",
        "python",
        "splunk_mcp.py",
        "stdio"
      ],
      "env": {
        "SPLUNK_HOST": "192.168.129.131",
        "SPLUNK_PORT": "8089",
        "SPLUNK_USERNAME": "mcpuser",
        "SPLUNK_PASSWORD": "<see ../../SOC-Automation-Project.md>",
        "SPLUNK_SCHEME": "https",
        "VERIFY_SSL": "false"
      }
    }
  }
}
```

Quit Claude Desktop completely (right-click in system tray → Quit; do not just close the window). Relaunch. Settings → Developer should show `splunk` as connected.

## Claude Code setup

Use the CLI rather than editing JSON:

```bash
# Substitute <password> with the value from SOC-Automation-Project.md before running
claude mcp add splunk -s local \
  -e SPLUNK_HOST=192.168.129.131 \
  -e SPLUNK_PORT=8089 \
  -e SPLUNK_USERNAME=mcpuser \
  -e 'SPLUNK_PASSWORD=<password>' \
  -e SPLUNK_SCHEME=https \
  -e VERIFY_SSL=false \
  -- uv --directory 'F:/Claude_Code/SOC_Automation_Project/splunk-mcp-main/splunk-mcp-main' run python splunk_mcp.py stdio
```

The single-quoting on `'SPLUNK_PASSWORD=<password>'` matters in bash — if the password contains `!` (or other history-expansion chars), it will be mangled if unquoted.

`-s local` ties the MCP to this project directory and keeps it private to this machine.

After running the command, restart VS Code (or reload the Claude Code panel) so the new MCP loads.

## Verification

In a Claude Code session inside this project, ask:

> "Using the splunk MCP, list available indexes"

Expected: it calls the MCP and returns at minimum `mydfir-project` plus the Splunk default indexes.

If it says it doesn't have access, check `claude mcp list` from the terminal — the entry should exist and show "✓ Connected."

## Common failures

| Symptom | Likely cause |
|---|---|
| MCP shows "failed" in Claude Desktop developer panel | `poetry` not installed (default video config) — switch to `uv` |
| Connection refused on 8089 | Used 8000 (web UI) instead of management API port |
| 401 from Splunk | Wrong username or password; or `mcpuser` doesn't have search permissions |
| `command not found: uv` | `uv` not on PATH — confirm with `where uv` and use absolute path if needed |
| MCP doesn't appear in Code after `claude mcp add` | VS Code needs a reload; or the command was run outside the project directory |
