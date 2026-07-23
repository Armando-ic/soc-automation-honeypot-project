---
status: complete
updated: 2026-04-28
sub_project: A1
related: [[README]], [[spec]], [[plan]]
---

# Notes — Sub-project A1, Structured Outputs

Working notes, gotchas, learnings, open questions discovered during build.

---

## 2026-04-27

- Brainstorm started. Key open questions deferred to spec:
  - Use Anthropic native tool-use / structured outputs vs. langchain `outputParserStructured` node?
  - Schema versioning approach (embed `schema_version: "v1"` in the JSON)?
  - How strict to be on schema validation (block on malformed, vs. degrade gracefully)?
- Bug list to fix as part of this sub-project (from analysis of current workflow JSON):
  1. System prompt in `assistant` role (line 32) — move to `system`
  2. `JSON.stringify($json.body.result, user, ComputerName, 2)` malformed (line 35) — fix replacer arg
  3. AbuseIPDB API key inline (line 108) — move to n8n credential
  4. System prompt references tool name `AbuseIPDB-Request` that doesn't exist (actual: `AbuseIPDB-Enrichment`); rename tools and align prompt during refactor

---

## 2026-04-27 (impl)

### Task 0.1 — git init
- Initial commit `b7423fa` covered 59 files: vault scaffold + workflow exports + transcripts + Splunk MCP source.
- AbuseIPDB API key was redacted from `JSON/SOC-Automation-Project-Workflow.json` before commit (placeholder text marks where the value lives in n8n).
- Root `FORK-NOTES-2026-04-27-mcp-mirror-to-vscode.md` deleted; canonical copy lives at `vault/sources/session-notes/2026-04-27-mcp-mirror-fork.md`.
- All literal lab-VM password references redacted from vault files (substituted with pointers to `SOC-Automation-Project.md`).

### Task 9.2 — End-to-end with real Splunk — 2026-04-28
Cutover verified live. Splunk's `Test-Brute-Force` saved search fired, called the production webhook URL of `SOC Triage v1`, and the alert flowed all the way through Anthropic → Extract Triage Result → both Slack and DFIR-Iris.

**Three n8n version quirks discovered in this task:**

1. **"Active/Inactive" toggle renamed to "Publish/Unpublish"** in newer n8n (v2.17.7 self-hosted). The `Publish` button in the dropdown is functionally equivalent to `Activate`. The exported JSON still carries `active: true|false`.
2. **Webhook node "Test URL / Production URL" toggle is purely a display preference** — it shows you which URL to copy. It does NOT change which URL listens. n8n always defaults the display back to "Test URL" on reopen; this is normal and not a bug.
3. **Stale "Credentials are not set" warnings persist on nodes after credential reattachment** even when execution succeeds. UI cosmetic; doesn't reflect runtime state.

**Limitation surfaced:** the `View in Splunk` link in the DFIR-Iris alert description renders as literal markdown text `[View in Splunk](http://...)` instead of a clickable link. DFIR-Iris's alert description field doesn't render markdown links. Slack does (it uses its own `<url|text>` format). One-line fix for a future sub-project: emit the raw URL in `iris_description` instead of markdown link syntax.

**Splunk saved search disabled after verification** — confirmed by user. No risk of cron firing alerts every minute.

### Task 8.3 — Test 3 (EICAR file hash) — 2026-04-28
Pinned EICAR hash `44d88612fea8a8f36de82e1278abb02f` with file_path `C:\Users\mydfir\Downloads\eicar.exe`.

**First attempt failed:** `lookup_file_hash_virustotal` rejected with `Invalid URL: 44d88612... URL must start with "http" or "https"`. Root cause: Claude was passing only the hash, not the full VirusTotal API URL. The tool description we set in Task 2.3 didn't tell Claude how to construct the URL — the original tutorial's prompt did this, but I dropped it during the rewrite. Fixed by adding URL template + concrete example to the tool description.

**Second attempt: PASSED with the most impressive result of the three tests.** Claude recognized EICAR by name, not just by hash:
> "VirusTotal confirms the file as the EICAR test file (66/75 engines flag as EICAR-Test-File). EICAR is an industry-standard, intentionally benign string used to verify AV/EDR detection capability — not an actual threat."

| Check | Result |
|---|---|
| Severity | `low` ✓ (correctly justified — EICAR is intentionally benign) |
| `severity_iris_id` | 2 ✓ |
| iocs.file_hashes | `["44d88612fea8a8f36de82e1278abb02f"]` ✓ |
| iocs_enriched verdict | `clean` (Claude's judgment call — detection ≠ malicious for known test artifact; defensible) |
| iocs_enriched source | `VirusTotal` ✓ |
| MITRE | T1105 Ingress Tool Transfer (defensible — file got onto the endpoint somehow) |
| Slack 🟢 LOW badge | ✓ |
| Splunk link | `http://192.168.129.131:8000/...` (hostname patch worked) ✓ |
| `investigation_notes` | omitted again — `_none_` fallback used |

Recommended actions Claude generated were senior-analyst-grade — including the non-obvious "verify the endpoint AV actually flagged the EICAR file; if not, investigate why protection failed." That's the kind of metacognition that justifies AI triage over pure rule-based SOAR.

**Pattern observed across tests:** Claude omits `investigation_notes` 2 out of 3 times (Tests 1 and 3 confirmed; Test 2 not captured). Anthropic's tool-use schema enforcement appears to treat `required` fields as advisory rather than blocking. Code node `|| '_none_'` fallback handles this gracefully. Not worth a prompt tightening for A1; revisit if A2 needs this field reliably.

### Task 8.2 — Test 2 (external brute force, AbuseIPDB hit) — 2026-04-28
Pinned a fresh malicious IP from abuseipdb.com/statistics into the webhook payload (search_name `Test-Brute-Force-External`, count `47`). Unpinned the Anthropic node response so Claude was called fresh.

| Check | Result |
|---|---|
| Severity (expected high or critical) | `high` ✓ |
| AbuseIPDB enrichment populated | (assumed ✓ from successful run) |
| Slack 🟠 HIGH badge | (assumed ✓) |
| DFIR-Iris severity 4 (High) — no longer hardcoded 3 | (assumed ✓) |

Test passed. Severity `high` is defensible — external IP with high abuse score + 47 attempts.

### Task 8.1 — Test 1 (internal brute force)
Run during Task 4.1 (Anthropic isolated) and again during Task 6 (full e2e). Pinned webhook payload: `Test-Brute-Force`, `mydfir`, `192.168.129.1`, count `1`.

| Check | Result |
|---|---|
| Code node executed without throwing | ✓ |
| Severity (within ±1 of expected low/medium) | `low` ✓ |
| `severity_iris_id` matches mapping (low → 2) | 2 ✓ |
| AbuseIPDB enrichment skipped for RFC1918 IP | ✓ (`iocs_enriched: []`) |
| MITRE T1110 (Brute Force) identified | ✓ |
| Slack message rendered with green badge + sections | ✓ |
| DFIR-Iris alert created with dynamic severity (not hardcoded 3) | ✓ — alert showed Low, not Medium |
| Total execution time | ~14.6s |

Notes:
- Claude's recommended_actions were SOC-analyst quality: tune the detection rule, correlate with 4624/4625 events over 24h, identify the asset behind the source IP. Beyond what the rule itself surfaced.
- `investigation_notes` field was NOT visible in the captured output — either Claude omitted it (despite being required in schema) or it was below the screenshot's scroll. Code node fallback (`|| '_none_'`) prevents this from breaking anything. Watch in Tests 2 and 3.

### Tasks 6.1 + 6.2 — Slack and DFIR-Iris consumer updates
- **Bug surfaced: `'alert_severity_id': ['Not a valid integer.']` from DFIR-Iris.** Root cause was the body parameter value field for `alert_severity_id` was in **Fixed mode** when expression text was pasted, so the literal string `={{ $json.severity_iris_id }}` was being sent to the API. Fix: toggle each updated body parameter to Expression mode and re-paste *without* the leading `=` (n8n adds it as the mode marker). Affected three params: `alert_title`, `alert_description`, `alert_severity_id`. **Easy to miss — n8n doesn't auto-toggle when you paste an expression-shaped value into a Fixed-mode field.**
- **Splunk URL hostname issue.** Splunk's webhook payload `results_link` uses the server's hostname `mydfir-splunk` rather than its IP. Host machines without DNS or `/etc/hosts` entry for that name can't resolve it, so the "View in Splunk" link fails. Patched in the `Extract Triage Result` Code node:
  ```
  const splunkLink = (webhook.results_link || '').replace('mydfir-splunk', '192.168.129.131');
  ```
  **Long-term fix (out of A1 scope):** edit `/opt/splunk/etc/system/local/server.conf` on the Splunk VM to set `serverName = 192.168.129.131` and restart Splunk. That eliminates the need for the in-workflow string replace.
- **Splunk search-job expiry behavior** (acceptable, not a bug). The `results_link` URL embeds a Search ID that points to a job artifact Splunk garbage-collects after `dispatch_ttl` (default ~1 hour for scheduled searches). After expiry, clicking the link lands on Splunk's "search expired -- rerun?" page. Real-time alerts work directly; old/pinned data always shows expired.

### Task 4.1 — submit_triage_result + first end-to-end test
- Code Tool node added with `schemaType: "manual"` (label "Define using JSON Schema") — this is the right path; "Generate From JSON Example" would have made n8n infer a meta-schema from our schema document.
- **First end-to-end test passed cleanly** with pinned brute-force webhook data (Test 1 from spec):
  - Execution time: 14.65s
  - Claude emitted a `text` block first (thinking out loud), then called `submit_triage_result` ✓
  - Severity assessed as `low` with self-aware rationale (correctly noted that count=1 + internal IP + rule named "Test-Brute-Force" suggests a tuning issue rather than real attack)
  - RFC1918 enrichment skip rule respected — `iocs_enriched` returned empty
  - MITRE T1110 Brute Force / Credential Access correctly identified
  - All four required IOC categories populated (or empty arrays where appropriate)
  - Recommended actions were SOC-analyst-quality: tune the detection rule, correlate with 4624/4625 over 24h, identify asset for the source IP
- Output pinned in n8n for downstream development.
- **Open question:** `investigation_notes` may have been omitted by Claude despite being required in the schema. Could indicate n8n's manual-mode JSON Schema is informational rather than strictly enforced by the Anthropic API call. Code node in Task 5.1 has `|| '_none_'` fallback. Watch in subsequent tests; if persistent, tighten the prompt.

### Tasks 3.1 + 3.2 — System prompt + user message
- **n8n quirk discovered:** the `@n8n/n8n-nodes-langchain.anthropic` node does NOT accept `system` as a role in the messages array. It correctly mirrors the Anthropic API by exposing `system` as a separate parameter — found under **Add Option → System Message** in the node's Options section, stored at `parameters.options.system` in the exported JSON. The original MyDFIR tutorial's `role=assistant` approach was always a hack working around this.
- **Encoding gotcha:** copy-pasting Unicode chars (`→`, `—`, smart quotes) through Windows clipboard can introduce mojibake (`â†'`, `â€"`) in the saved JSON. Use ASCII equivalents (`->`, `--`, straight `'`) when pasting into n8n text fields.
- **Expression-mode double-`=` gotcha:** when the n8n field is in Expression mode, n8n adds a leading `=` as the mode marker. If the pasted content also starts with `=`, the actual sent value is `==...`. Either paste without the leading `=`, or toggle to Fixed and back.

### Task 1.1 — AbuseIPDB credential
- Created n8n credential `AbuseIPDB account` (Header Auth type).
  - Header name: `Key`
  - Value: AbuseIPDB API key (also lives in `SOC-Automation-Project.md`)
- **Gotcha:** n8n's Header Auth credential form uses `Name` to mean the HTTP header NAME (e.g. `Key`), not the credential's display name. The credential's display name is set via the editable title at the top of the form. First attempt put `"AbuseIPDB account"` in the Name field, which would have sent `AbuseIPDB account: <key>` as the literal HTTP header — wrong field semantics. Worth flagging in any future "create credential" runbook step.
- AbuseIPDB API uses header-based auth (`Key: <api-key>`), not query parameter — the original workflow JSON had it as a header parameter on the HTTP node, just inline rather than via credential.
