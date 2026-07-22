---
status: active
updated: 2026-05-26
related: [[architecture/current-state]], [[workflows/soc-triage-pipeline]], [[decisions/0007-remove-slack-iris-native-gate]], [[subprojects/2026-05-23-azure-port/runbook]]
---

# DFIR-Iris

## What it is

Open-source incident response case management. Receives alerts from the n8n workflow, organizes them into investigations. Runs in Docker via docker compose on Ubuntu Server 24.04. **As of P2 (2026-05-26) running on Azure IaaS** (`vm-soc-v2-iris` in `rg-soc-v2-azure-central-us`); the local-VMware host (`MyDFIR-DFIR-IRIS-VM-v2`, 192.168.129.133) was decommissioned during P2 Task 22 and archived to `F:\VMs\MyDFIR-DFIR-IRIS-VM-v2\`.

## Configuration (P2 / Azure)

| | |
|---|---|
| Host | `vm-soc-v2-iris` (Azure VM, Central US, `Standard_D2s_v3`) |
| Public Web UI | https://x.x.x.x (HTTPS, self-signed cert; NSG-restricted to home IP) |
| Private API endpoint | https://10.0.0.7/api/* (intra-VNet — n8n-to-IRIS leg) |
| Version | v2.4.22 (commit `f75e56fb` — matches v1 rebuild exactly; IOC type IDs and severity IDs unchanged) |
| Source | https://github.com/dfir-iris/iris-web (git tag `v2.4.22`) |
| Run command | `cd ~/iris-web && docker compose up -d` (modern plugin) |
| Admin user | `administrator` (password set via `IRIS_ADM_PASSWORD` in `.env` — explicit, not log-scraped) |
| API key | Set via `IRIS_ADM_API_KEY` in `.env` — known from first start, no UI regeneration needed |
| Containers | `iriswebapp_db` (postgres) · `iriswebapp_app` · `iriswebapp_nginx` (with healthcheck) · `iriswebapp_rabbitmq` · `iriswebapp_worker` |
| Auto-shutdown | 11 PM Eastern |

See [[subprojects/2026-05-23-azure-port/runbook]] for operational commands; gotcha §I1–§I4 cover IRIS-specific pitfalls.

## Migrated from v1 (decommissioned 2026-05-26)

Original local IRIS on `MyDFIR-DFIR-IRIS-VM-v2` (192.168.129.133) was decommissioned during P2 Task 22. **No Postgres `pg_dump`/restore was performed** (deviation from plan Task 19's original spec): the v1 IRIS itself was a 2026-05-12 fresh rebuild with minimal historical alerts (max alert #64 per 2026-05-19 demo log) — migration cost outweighed the benefit. Azure IRIS started clean and accumulated alerts organically during P2 verification (alerts 1–217 to date).

## Setup gotchas (validated 2026-05-12 v1 rebuild; updated 2026-05-26 for P2 / Azure)

### `depends_on` blocks crash older docker-compose (**OBSOLETE under modern compose-plugin**)

In v1 (using `docker-compose 1.29.2` via apt), the shipped `docker-compose.base.yml`'s three `depends_on:` directives failed and required commenting out via an awk pass.

**No longer required on P2 / Azure** — the modern `docker compose v5.1.4` plugin handles short-form `depends_on` cleanly. P2's IRIS install confirmed all 5 containers came up in correct order on first try with no workaround. Section preserved for context if anyone falls back to legacy `docker-compose` 1.29.x.

```bash
# v1-era awk workaround (NOT needed on P2):
awk '
  /depends_on:/ { commenting = 1; print "#" $0; next }
  commenting && /^[[:space:]]+- / { print "#" $0; next }
  commenting { commenting = 0 }
  { print }
' docker-compose.base.yml.bak > docker-compose.base.yml
```

### `.env` must be fresh-copied from `.env.model` after git clone

(Persists in P2.) The repo at v2.4.22 ships a 36-byte `.env` that's NOT a valid environment file (parses to nothing). Postgres then fails to start with `POSTGRES_PASSWORD not specified`. Fix: explicitly `cp .env.model .env` after `git checkout v2.4.22`, overwriting the shipped stub.

### Admin password and API key can be set explicitly in `.env` (P2 improvement over v1 log-scraping)

V1 relied on the `iriswebapp_app` container's first-run random password printed once to stdout (capture via `docker-compose logs app | grep -i "password"`).

**P2 / Azure pattern is cleaner:** set `IRIS_ADM_PASSWORD=...` and `IRIS_ADM_API_KEY=...` explicitly in `.env` (both documented as optional in `.env.model`, commented out by default). Uncomment + set both before first `docker compose up -d`. Result: known password + known API key from first start — no log-scraping, no UI regeneration. Useful for automation and reproducible rebuilds.

### Benign DB log warning during first start

Don't chase: `"duplicate key value violates unique constraint groups_group_name_key" Key (group_name)=(Analysts) already exists`. IRIS's init script tries to insert default groups and catches the conflict downstream. Harmless.

## API integration

- Used by n8n workflow to create alerts via `POST /alerts/add`
- Full endpoint reference: [DFIR-Iris OpenAPI spec](../../../JSON/IRIS-2.0.4-OpenAPI-specification.json) at project root
- Currently used: `/alerts/add` (with `alert_iocs` body field, A2+); `/alerts/escalate/{alert_id}` (A2 escalation gate)
- `/alerts/add` accepts `alert_iocs` and `alert_assets` arrays at creation time — IOCs ride along with the alert and get UUIDs assigned for later import via escalation
- `/alerts/escalate/{alert_id}` promotes an alert into a new case; body's `iocs_import_list` is an array of those UUIDs to copy into the case-level threat-intel database
- Useful unused endpoints for future work: `/case/ioc/add` (add IOC directly to an existing case), `/manage/cases/add` (create case standalone), `/cases/{id}/notes/add` (case notes)

## Required fields when creating an alert

| Field | Current value | Notes |
|---|---|---|
| `alert_title` | Splunk search name | Comes from webhook |
| `alert_description` | AI-generated text | Currently freeform Claude output; becomes structured per A1 |
| `alert_severity_id` | Looked up from Claude's `severity` via the catalog table below | A2: corrected from A1's wrong table; see "Severity IDs" section |
| `alert_status_id` | Hardcoded `1` — but **maps to "Unspecified" on v2.4.22**, not "New" as previously assumed | Documented inversion — see Alert Status IDs section below; cosmetic for now, fix when next revising the workflow |
| `alert_customer_id` | Hardcoded `1` | Single-tenant lab — fine |

## IOC type IDs (captured 2026-04-28)

Required by A2's `Extract Triage Result` Code node when building the `alert_iocs` body for `POST /alerts/add`. **Re-capture if Iris is upgraded** — IDs are deployment-specific (the catalog has 160 entries; positions can shift across versions).

| Our schema key | Iris `type_name` | Iris `type_id` |
|---|---|---|
| `ip`     | `ip-src` | **79** |
| `domain` | `domain` | **20** |
| `md5`    | `md5`    | **90** |
| `sha1`   | `sha1`   | **111** |
| `sha256` | `sha256` | **113** |

Source: `GET /manage/ioc-types/list` on the Iris instance at `x.x.x.x` (public) / `10.0.0.7` (private, intra-VNet).

Notes on the choices:

- **`ip-src` (79) over `ip-dst` (77).** Splunk alerts deliver the *source* IP of the attacker (the IP attempting failed logons, etc.) — matches `ip-src`'s description "A source IP address of the attacker." If a future detection emits a destination IP (e.g., outbound C2), the Code node's `resolveIrisTypeId` should be extended to handle both — A1's `iocs_enriched.ioc_type` enum currently treats all IPs as a single category.
- **No URL type yet.** Iris has `url` (id 141) but A1's schema doesn't separate URLs from domains. If A3+ adds URL extraction from alerts, register `url` here and extend the schema.
- **No hostname type yet.** Iris has `hostname` (id 69) for "full host/dnsname of an attacker," but A1's `iocs.hosts` array tracks internal hostnames (the affected endpoint), which we don't push to threat intel. Distinct concept; deliberately not mapped.

To re-capture:

```bash
curl -ks -H "Authorization: Bearer <iris-api-key>" \
  https://x.x.x.x/manage/ioc-types/list \
  | python -c "
import json, sys
d = json.load(sys.stdin)['data']
for t in d:
    if t['type_name'] in ('ip-src', 'domain', 'md5', 'sha1', 'sha256'):
        print(t['type_name'], '->', t['type_id'])
"
```

## Alert status IDs — captured 2026-05-12

| `alert_status_id` | `status_name` |
|---|---|
| 1 | Unspecified |
| (others to be captured when needed) | — |

The workflow currently hardcodes `alert_status_id=1` (per the table in "Required fields"). On v2.4.22 this lands the alert as "Unspecified" status — not what was historically intended. Recapture and pick the appropriate ID (likely "New") in a future workflow revision.

To recapture the full status catalog:

```bash
curl -ks -H "Authorization: Bearer <iris-api-key>" \
  https://x.x.x.x/manage/alert-status/list | python -m json.tool
```

## Severity IDs (captured 2026-04-28, reverified 2026-05-12 — unchanged)

Required by `Extract Triage Result`'s severity-mapping table (`sevId`). **Iris severity IDs are non-linear** — they do not follow severity order. **Re-capture if Iris is upgraded.**

Live catalog from `GET /manage/severities/list`:

| `severity_id` | `severity_name` |
|---|---|
| **1** | Medium |
| **2** | Unspecified |
| **3** | Informational |
| **4** | Low |
| **5** | High |
| **6** | Critical |

Code node mapping from Claude's `severity` enum:

| Claude `severity` | Iris `severity_id` |
|---|---|
| `low`      | 4 |
| `medium`   | 1 |
| `high`     | 5 |
| `critical` | 6 |
| (fallback for any unrecognized value) | 2 (Unspecified) |

**A1 had this wrong.** A1's table mapped `low→2, medium→3, high→4, critical→5`, which on this Iris instance silently produced Unspecified, Informational, Low, and High respectively — every alert was understated. The bug went undetected because A1 didn't capture the alert-creation response (the toggle A2's `alwaysOutputData` enabled, which surfaced `severity.severity_name` in the response body and made the mismatch visible). Fixed in A2 alongside the Code node rewrite.

To re-capture:

```bash
curl -ks -H "Authorization: Bearer <iris-api-key>" \
  https://x.x.x.x/manage/severities/list \
  | python -m json.tool
```

## `/alerts/escalate/{alert_id}` handler bugs (deployment-specific, captured 2026-04-29)

The Iris OpenAPI spec marks `case_tags` and `assets_import_list` as **optional** on the escalate request body. In practice, the handler in our running v2.4.22 deployment crashes with unhandled-`None` errors when either field is omitted:

| Field omitted | Server-side error |
|---|---|
| `case_tags` | `'NoneType' object has no attribute 'split'` — handler calls `.split(',')` on `case_tags` without null-check |
| `assets_import_list` | `'NoneType' object is not iterable` — handler iterates over `assets_import_list` without null-check |

**Always include both fields in the escalate body, even if empty:**

```json
{
  "iocs_import_list": [...],
  "assets_import_list": [],
  "case_tags": "soc-automation,a2,auto-escalated",
  "import_as_event": true,
  "note": "...",
  "case_title": "..."
}
```

`assets_import_list: []` and `case_tags: "anything"` are both safe degenerate values — the handler accepts them and creates a case with no assets and the given tag string. A2's `Build Escalate Body` Code node always includes both, so this isn't a current blocker; the rule is here so future integrators don't trim "optional" fields from the body and silently 500.

This is a Iris-side spec/implementation mismatch, not something we can fix from the integrator's side. Worth tracking against future Iris versions: the handler may pick up null-checks in a later release and the rule may relax. Re-test if Iris is upgraded.
