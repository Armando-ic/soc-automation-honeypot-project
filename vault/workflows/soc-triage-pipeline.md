---
status: active
updated: 2026-05-12
related: [[architecture/components/n8n]], [[architecture/components/dfir-iris]], [[architecture/components/claude-api]], [[decisions/0007-remove-slack-iris-native-gate]]
---

# SOC Triage Pipeline

The current production n8n workflow. Linear, single-path, ends at IRIS alert creation — human approval (was Slack-interactive in v2) moves to IRIS's native alert review per ADR 0007.

**Source of truth (JSON export):** [SOC-Triage-v3.json](../../JSON/SOC-Triage-v3.json)

**Workflow name in n8n:** `SOC Triage v3`

## Version history

| Version | Date | Notes |
|---|---|---|
| v0 | 2026-04-27 | Original tutorial workflow — `assistant`-role system prompt bug, malformed `JSON.stringify`, freeform Claude output, inline AbuseIPDB key |
| v1 | 2026-04-28 | A1 shipped — structured outputs via `submit_triage_result` tool + `Extract Triage Result` Code node |
| v2 | 2026-04-30 | A2 shipped — Iris Escalation Gate via Slack interactive Wait-resume URLs |
| **v3** | **2026-05-12** | **Slack removed; human approval moves to IRIS-native review (ADR 0007). Linear pipeline.** |

## v3 topology

```
Webhook                                                            ← Splunk saved-search webhook
   ↓
Message a model (Anthropic, claude-opus-4-7)                       ← Claude tier-1 triage
   ├── ai_tool: enrich_ip_abuseipdb                                ← Claude-callable on demand
   ├── ai_tool: lookup_file_hash_virustotal                        ← Claude-callable on demand
   └── ai_tool: submit_triage_result (toolCode, A1 structured-out)
       ↓
Extract Triage Result (Code node)                                  ← Builds Iris-shaped body from A1 struct
   ↓
Create Iris Alert (HTTP POST /alerts/add)                          ← Terminal — workflow ends here
```

7 nodes total (was 18 in v2). No branching, no waiting, no fan-out.

## Trigger

Splunk saved search **`T1059.001 - PowerShell Encoded Command`** (and any future saved searches added by D-series sub-projects) calls the webhook URL:

```
http://10.0.0.6:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd
```

The webhook path/GUID is preserved verbatim from v2 → v3 so the Splunk saved search needed no change at the v3 cutover (verified 2026-05-12: alert #4 fired end-to-end through the original webhook URL).

The webhook path is GUID-based but unauthenticated — anyone reachable on the n8n network can POST fake alerts. Auth hardening is deferred (was deferred in v0–v2 too; ADR 0007's scope doesn't change this).

## Credentials wired (4)

After the 2026-05-12 IRIS API key regen + workflow re-import, the n8n credential IDs are fresh (the old IDs `VozkiMP8QqbykLLj` / `IWEqjD1DvRajiKXy` / etc. are v2 artifacts).

| n8n credential type | Used by | Notes |
|---|---|---|
| `anthropicApi` | Message a model | Claude Opus 4.7 |
| `virusTotalApi` | lookup_file_hash_virustotal | VT account API key |
| `httpHeaderAuth` | enrich_ip_abuseipdb | AbuseIPDB; header `Key` = api key |
| `dfirIrisApi` | Create Iris Alert | Base URL `https://10.0.0.7`, API key regenerated 2026-05-12, **Ignore SSL Issues** enabled (self-signed cert) |

`slackApi` is no longer present in v3.

## What Claude does (system prompt)

Acts as a Tier-1 SOC analyst:
1. Summarize the alert (host, user, technique fingerprint).
2. Call enrichment tools (AbuseIPDB for IPs, VirusTotal for file hashes) when relevant IOCs appear in the alert payload.
3. Decode base64 payloads independently when encountered (no prompt addendum required for this — Claude does it natively; documented behavior since alerts #51/#52 on 2026-04-30, reproduced in alert #4 on 2026-05-12).
4. Assess severity against MITRE ATT&CK technique class.
5. Call `submit_triage_result` with structured output: `severity` (`low`/`medium`/`high`/`critical`), `iocs_enriched[]`, `mitre_techniques[]`, etc.

## What the workflow does with Claude's output

`Extract Triage Result` Code node reads `submit_triage_result`'s structured output and builds the IRIS POST body:
- `alert_title` ← Splunk search_name
- `alert_description` ← Claude's prose summary
- `alert_severity_id` ← mapped from Claude's `severity` enum per the table in [[architecture/components/dfir-iris#severity-ids-captured-2026-04-28]]
- `alert_status_id: 1` (hardcoded — see Known issues §1)
- `alert_customer_id: 1` (hardcoded; single-tenant lab)
- `alert_iocs` ← built from `iocs_enriched` per the IOC-type-ID mapping in dfir-iris.md (only IOCs with mapped type IDs are included; unmapped types are skipped)

Then `Create Iris Alert` HTTPs POSTs to `https://10.0.0.7/alerts/add` with the Bearer API key. Self-signed cert tolerance is enabled on the credential.

## Pinned test data

The v3 workflow inherited the v2 pinned data on the Webhook node — represents a single PowerShell-encoded-command event (the D1 worked example). Used to exercise the workflow without firing a real Splunk alert.

## Known issues (post-v3)

Inherited from v2, not yet addressed:

1. **`alert_status_id=1` maps to "Unspecified" on v2.4.22**, not "New" as historically documented. Verified 2026-05-12 against the rebuilt IRIS instance. The workflow's hardcoded value should be re-derived from `GET /manage/alert-status/list`; alternately the workflow could leave the field unset and let IRIS's default apply. Cosmetic for portfolio purposes; flagged as a future fix.
2. **Webhook is unauthenticated.** Network-reachability is the only access control. Acceptable for a lab on a private NAT subnet; would need hardening for production.
3. **Severity-stamping inconsistency** persists in v3 — Claude's prose mention of severity occasionally diverges from the structured `severity` field, OR the structured severity reflects payload-content benignness rather than technique-class risk. Documented in [[../subprojects/2026-04-30-detection-foundations/notes#phase-11-2026-05-12--post-rebuild-revalidation-on-rebuilt-lab]] gotcha §4.

## Re-import procedure (when standing up a fresh n8n)

1. Import `JSON/SOC-Triage-v3.json` via n8n's *Workflows → Import from File*.
2. Verify the Webhook node's path is `db7245f7-8451-4bea-b47d-f6ad35b818cd` (preserved on import; if n8n changes it, manually patch back).
3. Recreate the 4 credentials with values from gitignored `SOC-Automation-Project.md`. Bind each to the corresponding node.
4. IRIS credential: enable **Ignore SSL Issues** (self-signed cert at 10.0.0.7).
5. Activate the workflow.
6. Verify via curl-probe against the webhook URL — should return `{"message":"Workflow was started"}` and produce a new IRIS alert within ~30 seconds.

A worked example of step 6 (synthetic Splunk-shape payload curl + alert verification) is captured in the Phase 11 section of [[../subprojects/2026-04-30-detection-foundations/notes]].

## n8n environment quirks worth knowing

- **`N8N_SECURE_COOKIE=false`** is required on the compose env block for non-localhost HTTP access in current `n8nio/n8n:latest` (added by default in versions post-1.X). Without it, the `/setup` page returns a "secure cookie required" wall.  Captured in [[../architecture/components/n8n#known-quirks-post-rebuild-2026-05-12]].
- **docker-compose 1.29.2's `--force-recreate` flag** triggers a `KeyError: 'ContainerConfig'` against newer Docker (29.x). Workaround: `docker-compose down && docker-compose up -d` instead of `up -d --force-recreate`.

See [[../architecture/components/n8n]] for the full component reference.
