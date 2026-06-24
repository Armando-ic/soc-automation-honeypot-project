# CrowdStrike Falcon API — integration notes (for Plans 0B & 0D)

Distilled from the official n8n template `JSON/Analyze_Crowdstrike_detections.json`
(2023, "Analyze CrowdStrike detections → VirusTotal → Jira → Slack") plus CrowdStrike
API knowledge. **Confirm exact endpoint versions/scopes against the live Falcon API
docs / Swagger at build time** — versions drift, and our tenant's cloud differs.

> Provenance tags: **[TEMPLATE]** = verified from the n8n export. **[STD]** = standard
> documented Falcon endpoint. **[VERIFY]** = modern direction; confirm current path/version.

---

## 1. Auth — use n8n's native credential, no manual OAuth

- The HTTP Request nodes use `authentication: predefinedCredentialType`,
  `nodeCredentialType: crowdStrikeOAuth2Api`. **[TEMPLATE]**
- n8n manages the OAuth2 **client-credentials** flow (token mint + refresh) for you —
  the same HTTP-Tool pattern already used for AbuseIPDB / VirusTotal. No manual
  `POST /oauth2/token`. **[TEMPLATE]**
- You create the credential from a Falcon **API client** (client_id + secret) with
  explicit **API scopes**. Minimum scopes for our use **[STD / VERIFY]**:
  - **Alerts: Read** (or legacy **Detections: Read**) — pull detections.
  - **Hosts: Read** and **Hosts: Write** — required for the `Contain` / `Lift
    Containment` device action.
  - (Real Time Response / RTR is a *separate* scope set — not needed for network
    containment; only if we later script on-host commands, which is Pro/Enterprise.)

## 2. Cloud-specific base URL (gotcha)

The template hardcodes **`https://api.us-2.crowdstrike.com`**. **[TEMPLATE]** The API base
is **per-cloud** — use whatever our Falcon tenant is provisioned in: **[STD]**
- us-1 → `https://api.crowdstrike.com`
- us-2 → `https://api.us-2.crowdstrike.com`
- eu-1 → `https://api.eu-1.crowdstrike.com`
- us-gov-1 → `https://api.laggar.gcw.crowdstrike.com`

The dashboard/UI links are likewise per-cloud (template uses `falcon.us-2.crowdstrike.com`).

## 3. Pull detections — two-step fetch

**Legacy Detects API (what the template uses):** **[TEMPLATE]**
1. `GET /detects/queries/detects/v1?filter=status:'new'` → returns detection IDs in `resources[]`.
2. `POST /detects/entities/summaries/GET/v1` body `{"ids":[<ids>]}` → full detection objects.

**Modern Alerts API (preferred for new builds — the Detects API is deprecated):** **[VERIFY]**
1. `GET /alerts/queries/alerts/v2?filter=<FQL>` → returns alert `composite_id`s.
2. `POST /alerts/entities/alerts/v2` body `{"composite_ids":[…]}` → full alert objects.
3. `PATCH /alerts/entities/alerts/v3` → update alert status (e.g. new→in_progress→closed).

> **Decision for 0D:** build on the **Alerts API**; treat the template's Detects shape as
> the field reference. Confirm exact v2/v3 paths + FQL filter fields against current docs.

## 4. Detection data shape (triage input + Sigma fodder)

Each detection `resource` has a `device` object and a `behaviors[]` array. **[TEMPLATE]**

- `device`: `hostname`, `device_id` (← key for containment), `local_ip`, `external_ip`,
  `os_version`, `platform_name`.
- each `behaviors[]` entry:
  - file: `sha256`, `md5`, `filename`, `filepath`, `cmdline`, `alleged_filetype`
  - identity: `user_name`, `user_id`
  - **MITRE**: `technique_id` (e.g. `T1003`), `technique`, `tactic`, `tactic_id`
  - scoring: `severity`, `confidence`, `scenario` (e.g. `NGAV`, `credential_theft`)
  - IOC: `ioc_type`, `ioc_value`, `ioc_source`, `ioc_description`
  - lineage: `parent_details.parent_sha256`, `parent_details.parent_cmdline`
  - `control_graph_id` (→ builds the Falcon UI detection link)
  - `pattern_disposition_details` (see §6)
- detection-level: `max_severity_displayname` (Low/Medium/High/Critical), `detection_id`,
  `quarantined_files[]`.

The sample data includes a **mimikatz credential-theft** detection (`T1003`,
`scenario: credential_theft`) — exactly the post-exploitation a honeypot attacker runs.
`technique_id` flowing straight from the detection feeds our Qdrant MITRE RAG + Sigma generation.

## 5. Response action — `Contain` / `Lift Containment` (job responsibility #5)

Network-isolate (or release) a host by `device_id`: **[STD]**
- Contain: `POST /devices/entities/devices-actions/v2?action_name=contain` body `{"ids":["<device_id>"]}`
- Release: `POST /devices/entities/devices-actions/v2?action_name=lift_containment` body `{"ids":["<device_id>"]}`
- Needs **Hosts: Write** scope. In our SOAR this is the verifier-passed, high-severity,
  human-gated auto-response step (spec §5.3). n8n exposes this as a device action; if the
  native operation isn't present, call it via the HTTP Request node with the same OAuth credential.

## 6. Detect-only verification (critical for the honeypot)

We run Falcon in **detect-only** so the attack proceeds (full kill chain) while Falcon still
detects. Verify via each behaviour's `pattern_disposition_details`: **[TEMPLATE]**
- In the template's *sample* (prevention mode): `process_blocked: true`, `quarantine_file: true`.
- **For our honeypot we want these `false`** (`process_blocked: false`, `quarantine_file: false`,
  `kill_process: false`, etc.) — that's the signal the prevention policy is detect/monitor-only.
- Falcon **Go** is set-and-forget NGAV, so its policy granularity for detect-only may be coarse —
  **validate this during the 15-day trial** (a Pro/Enterprise trial gives finer policy control).

## 7. Honest caveats inherited from the template (do NOT copy blindly)

- **Legacy Detects API** (`"powered_by":"legacy-detects"`, 2023) — migrate to Alerts API (§3).
- **Daily Schedule Trigger is far too slow for a honeypot** — use a tight poll (1–5 min) or the
  **Event Streams / datafeed API** (`GET /sensors/entities/datafeed/v2`) **[VERIFY]** for near-real-time.
- **VT URL typo** in the template (`{{ $json.dsha256 }}` — should be `sha256`); the author flagged it.
- CrowdStrike/Jira/Slack nodes ship **disabled** with **pinned sample data** (safe-import pattern) —
  re-enable + rebind credentials after import.
- `continueOnFail: true` on the VT nodes is a good **resilience** pattern to keep (an enrichment
  miss shouldn't kill triage).

## 8. How this maps onto our plans

- **Plan 0B (Falcon):** auth = native `crowdStrikeOAuth2Api` credential (scopes: Alerts:Read,
  Hosts:Read+Write); pin our tenant's **cloud base URL**; configure **detect-only** and verify via
  `pattern_disposition_details` (§6); validate the `Contain` round-trip (§5).
- **Plan 0D (n8n wiring):** fork this template as the **Falcon detections poll ("path b")** skeleton —
  keep the OAuth credential, two-step fetch, split-per-detection/per-behaviour iteration, and
  `continueOnFail` enrichment — then replace the Set→Jira→Slack tail with our **Claude Opus triage +
  verifier gate + enrichment roster (GreyNoise/AbuseIPDB/URLscan beside VT) + Qdrant tool + DFIR-Iris +
  Discord + Falcon `Contain` + run-log**. Swap the daily schedule for a tight poll/stream, build on the
  **Alerts API**, and fix the VT typo.
