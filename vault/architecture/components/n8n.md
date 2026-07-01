---
status: active
updated: 2026-05-26
related: [[architecture/current-state]], [[workflows/soc-triage-pipeline]], [[decisions/0007-remove-slack-iris-native-gate]], [[../subprojects/2026-05-23-azure-port/runbook]]
---

# n8n

## What it is

Workflow automation engine playing the SOAR role. Runs in Docker via docker compose on Ubuntu Server 24.04. **As of P2 (2026-05-26) running on Azure IaaS** (`vm-soc-v2-n8n` in `rg-soc-v2-azure-central-us`); the local-VMware host (`MyDFIR-n8n-VM-v2`, 192.168.129.132) was decommissioned during P2 Task 21 and archived to `F:\VMs\MyDFIR-n8n-VM-v2\`.

## Configuration (P2 / Azure)

| | |
|---|---|
| Host | `vm-soc-v2-n8n` (Azure VM, Central US, `Standard_D2s_v3`) |
| Public Web UI | http://x.x.x.x:5678 (NSG-restricted to home IP) |
| Private webhook target | http://10.0.0.6:5678 (intra-VNet — Splunk-to-n8n leg) |
| Default port | 5678 |
| Run command | `cd ~ && docker compose up -d` (modern compose-plugin, not legacy `docker-compose`) |
| Image | `n8nio/n8n:2.21.7` (Docker Hardened Image, digest `sha256:9f1f8e4c…`, pulled 2026-05-25 — pinned to this digest for reproducible rebuilds) |
| Data volume | bind-mount `~/.n8n:/home/node/.n8n` (container runs as UID 1000 = `azureuser`) |
| Compose env | `N8N_HOST=x.x.x.x`, `N8N_PROTOCOL=http`, `N8N_SECURE_COOKIE=false`, `WEBHOOK_URL=http://x.x.x.x:5678/`, `GENERIC_TIMEZONE=America/New_York` |
| Docker / compose | Docker Engine + `docker compose v5.1.4` plugin (not legacy `docker-compose 1.29.x`) |
| Auth | **n8n native user management** (owner: `owner@example.com` / secrets file). **NOT `N8N_BASIC_AUTH_*`** — deprecated since n8n 1.0+ |
| Auto-shutdown | 11 PM Eastern |

See [[../subprojects/2026-05-23-azure-port/runbook]] for operational commands; gotcha §N1–§N5 cover community-node + UI pitfalls.

## Migrated from v1 (decommissioned 2026-05-26)

Original local n8n on `MyDFIR-n8n-VM-v2` (192.168.129.132) was decommissioned during P2 Task 21. Workflow JSON (`JSON/SOC-Triage-v3.json`) was re-imported on Azure; 4 credentials recreated from the gitignored secrets file. Webhook GUID `db7245f7-8451-4bea-b47d-f6ad35b818cd` survived JSON import unchanged (matches the v3-era GUID preserved during 2026-05-12 v1 rebuild specifically so Splunk needed no change).

## Configured credentials in n8n (post-2026-05-25 Azure install)

After the 2026-05-25 fresh n8n install on Azure, the credential IDs are again new — the workflow JSON's OLD credential IDs (`VozkiMP8QqbykLLj`, `IWEqjD1DvRajiKXy`, etc. from v1) don't exist on the rebuilt instance. Each credential must be re-bound to the corresponding node post-import.

| Credential | n8n type | Used by | Notes |
|---|---|---|---|
| Anthropic account | `anthropicApi` | Message a model node | API key from gitignored secrets file |
| VirusTotal account | `virusTotalApi` | lookup_file_hash_virustotal (AI tool) | API key from secrets file |
| AbuseIPDB account | `httpHeaderAuth` (Header Auth) | enrich_ip_abuseipdb (AI tool) | Header name `Key`, value is API key. **Migrated from v0-inline-key to credential during A1.** |
| DFIR IRIS account | `dfirIrisApi` (community node `n8n-nodes-dfir-iris` v2.0.3) | Add new Alert node | Host `https://10.0.0.7` (IRIS private IP — intra-VNet), API Version `2.0.4`, Use HTTP OFF, **Ignore SSL Issues ON** (self-signed). Bearer API key from `IRIS_ADM_API_KEY` in `~/iris-web/.env` on `vm-soc-v2-iris`. |

**Community-node swap (P2 deviation from v3 JSON):** The v3 workflow's "Create Iris Alert" was an `n8n-nodes-base.httpRequest` referencing a hand-registered `dfirIrisApi` custom credential type. On a fresh n8n install (no custom credential file), the JSON imports with a broken Iris node. P2 swapped this to the upstream community package `n8n-nodes-dfir-iris` v2.0.3 (`barn4k`) — more reproducible (one npm install vs. hunting for a custom credential file). See [[../subprojects/2026-05-23-azure-port/notes]] Task 15. The **`Add IOCs (JSON)`** field on this node MUST be `{{ $json.alert_iocs }}` raw — NOT `{{ JSON.stringify($json.alert_iocs) }}` (Gotcha §N1 in the P2 runbook; root-cause analysis at [[../subprojects/2026-05-23-azure-port/notes]] Task 19 gotcha #1).

**Slack credential intentionally absent** as of v3 (ADR 0007 — human approval moved to IRIS-native review).

## Workflows

- **SOC Triage v3** — current production workflow on the rebuilt n8n instance. Imported from `JSON/SOC-Triage-v3.json`. See [[workflows/soc-triage-pipeline]].
- Two templates imported for reference (carried forward through rebuild for documentation purposes — re-import them post-rebuild if you want them back; they're not loaded on the v2 VM by default):
  - `Phishing_analysis__URLScan_io_and_Virustotal_` — pattern reference for iteration, error gating, async waits
  - `My workflow 2` (Zendesk + Qdrant) — pattern reference for structured output parsing and RAG retrieval

## Known quirks (post-rebuild 2026-05-12)

### `N8N_SECURE_COOKIE=false` is required for LAN HTTP access

`n8nio/n8n:latest` (current image) defaults to `N8N_SECURE_COOKIE=true`, which blocks any non-localhost HTTP access with a "secure cookie required" wall on `/setup`. Three options:
- HTTPS via TLS reverse proxy (real fix — significant scope, deferred)
- `localhost` only (not viable — we need LAN access from Splunk and host browser)
- `N8N_SECURE_COOKIE=false` (pragmatic; this is what's set)

For a lab on a private NAT-only subnet this is fine. For internet-exposed deployment it would not be.

### docker-compose 1.29.2 `--force-recreate` was broken against newer Docker (**HISTORICAL — v1 only**)

In v1, `docker-compose up -d --force-recreate` failed with `KeyError: 'ContainerConfig'` in `/usr/lib/python3/dist-packages/compose/service.py` because newer Docker (29.x) deprecated that field in image inspect output. Workaround was: `docker-compose down && docker-compose up -d` instead of using `--force-recreate`.

**No longer applicable on P2 / Azure** — the modern `docker compose v5.1.4` plugin (replaces the legacy `docker-compose 1.29.x` Python tool) does not exhibit this bug. Section preserved for archive context.

## How to access (P2 / Azure)

- Web UI: http://x.x.x.x:5678
- SSH: `ssh -i C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem azureuser@x.x.x.x`
- See [[runbooks/n8n-workflow-deployment]] for deploying changes (note: runbook IPs need update if not yet refreshed)

## Wait-node resume URLs are signed (captured 2026-04-29)

n8n's Wait node, when in **On Webhook Call** mode, generates resume URLs of the form:

```
http://192.168.129.132:5678/webhook-waiting/<execution_id>?signature=<token>
```

The `signature` query parameter is computed server-side from execution data using a server secret — it is **unguessable and cannot be reconstructed manually**. Hitting `http://.../webhook-waiting/<execution_id>?decision=approve` (without the signature) returns `{"error": "Invalid token"}`.

**Always use `{{ $execution.resumeUrl }}`** in any node that constructs a resume URL (Slack URL buttons, email approval links, etc.). It populates with the full signed URL during expression resolution — confirmed to work even in nodes **before** the Wait node runs (e.g., a Slack post node upstream of Wait). When appending decision-or-other parameters, use `&` not `?` because the URL already has `?signature=...`:

```
{{ $execution.resumeUrl }}&decision=approve
{{ $execution.resumeUrl }}&decision=deny
```

Discovered while building [[../../subprojects/2026-04-28-iris-escalation-gate/spec]]'s Slack approval gate. The original spec assumed a manual-construction fallback was viable — it isn't, in this n8n version. See [[../../subprojects/2026-04-28-iris-escalation-gate/spec#errata-post-implementation-corrections]] entry E3 for the as-shipped pattern.

**Side benefit (security):** the signed-token requirement makes the access-control surface "anyone with the Slack message" rather than "anyone on the LAN who can guess execution IDs". Sub-project A2.5's signed-Slack-interactivity scope shrinks accordingly.

## Wait-node timeout doesn't set a `timedOut` field (captured 2026-04-29)

When a Wait node times out, n8n does **not** add a `timedOut: true` field to the output item. Instead, the upstream item passes through Wait unchanged — Wait acts as a no-op pass-through on timeout. There is no special marker distinguishing a timed-out resume from an unrelated upstream-data shape.

**Implication for downstream Switch design:** if a workflow's branching depends on whether the Wait timed out, branch on the **presence/value of expected resume-data fields** instead. For A2's approval gate, that means `$json.query.decision === 'approve'` and `=== 'deny'` are the active branches; a fallback (catch-all) branch handles timeout (and any other malformed resume).

Documented in [[../../subprojects/2026-04-28-iris-escalation-gate/runbook]]'s "Build new IOC types or new gated actions" section as the pattern future gated-action sub-projects (A3+) should reuse.
