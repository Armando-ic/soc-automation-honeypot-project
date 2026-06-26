# CrowdStrike Falcon API — integration notes (for Plans 0B & 0D)

Field shapes distilled from the official n8n template `JSON/Analyze_Crowdstrike_detections.json`
(2023), **confirmed and corrected against the live Falcon docs (developer.crowdstrike.com) on
2026-06-26** via a research+verify pass. Where the template and current reality disagree, current
reality wins — several template endpoints are now **dead** (see §3).

> **Provenance tags:**
> **[CONFIRMED 2026-06-26]** = verified against current official docs this session.
> **[TEMPLATE]** = from the 2023 n8n export — useful as a *field reference* only.
> **[STALE]** = superseded / decommissioned — **do not build on this.**

---

## 0. Trial & tier reality (decided for Plan 0B) [CONFIRMED 2026-06-26]

- The **15-day free, no-credit-card, self-service** trial still exists. Access is emailed **~24h**
  after the form (not instant); newly-enabled modules can take **~30 min** to go live.
- ⚠️ The trial **defaults to Falcon Go modules (NGAV only) — no EDR, no RTR.** Real EDR comes from
  **self-enabling the free "Falcon Insight XDR" module** from the in-console **CrowdStrike Store**
  during the trial. *Enable it first and confirm EDR detections + API access actually unlock in-trial*
  (the trial-edition Insight unlock is the one thing not officially guaranteed).
- **Sustained pricing (corrects the old "keep Go ~$30–60 for EDR" assumption — Go has NO EDR):**
  - Falcon **Go** — $59.99/device/yr — NGAV + Device Control + Mobile. **No EDR.** (max 100 devices)
  - Falcon **Pro** — $99.99/device/yr — adds firewall mgmt. **Still no EDR** (the standalone Pro
    marketing page wrongly lists EDR — trust the official comparison table, not that page).
  - Falcon **Enterprise** — $184.99/device/yr — **first tier with EDR (Insight XDR) + RTR.**
  - → **Sustained EDR ≈ $185/device/yr, not $60.** All three are self-service, no sales contract.
- **Plan 0B decision:** *trial-capture, decide keep/drop at trial end.* 0B provisions nothing paid.

## 1. Auth [CONFIRMED 2026-06-26]

- OAuth2 **client-credentials**: `POST {base}/oauth2/token` (form-encoded `client_id` + `client_secret`;
  `member_cid` optional). **30-minute** token. Revoke early: `POST {base}/oauth2/revoke`.
- **Create the API client** in the console: **Support and resources → API clients and keys → Add new
  API client.** The **secret is shown once**; the **Base URL** (your cloud) is shown in the same window.
- **n8n path:** the HTTP Request nodes use `authentication: predefinedCredentialType`,
  `nodeCredentialType: crowdStrikeOAuth2Api` — n8n mints/refreshes the token for you (same HTTP-Tool
  pattern as AbuseIPDB/VT). No manual `/oauth2/token`. **[TEMPLATE]**
- **Scopes for our build** (one client, superset so 0D needs no new client):
  **Alerts: Read, Alerts: Write, Hosts: Read, Hosts: Write, Event streams: Read.**
  - **0B minimum:** Alerts: Read + Hosts: Read + Hosts: Write.
  - **Do NOT** select the legacy **Detections** scope — its API is gone (§3).

## 2. Cloud-specific base URL [CONFIRMED 2026-06-26]

API base is **per-cloud**; the SDK auto-discovers it on auth for commercial clouds, but for raw HTTP
we hardcode it. Read **your** cloud from the Base URL shown at API-client creation (or the console
hostname, e.g. `falcon.us-2.crowdstrike.com` → us-2).

- us-1 → `https://api.crowdstrike.com`
- us-2 → `https://api.us-2.crowdstrike.com`
- eu-1 → `https://api.eu-1.crowdstrike.com`
- us-gov-1 → `https://api.laggar.gcw.crowdstrike.com` · us-gov-2 → `https://api.us-gov-2.crowdstrike.mil`

> **Our tenant cloud = TBD** — record it here once the trial client is created (the template's hardcoded
> `api.us-2.crowdstrike.com` is the template's tenant, not necessarily ours).

## 3. Pull detections — Alerts API (legacy Detects API is DEAD) [CONFIRMED 2026-06-26]

> ⚠️ **The legacy `/detects/*` service collection was DECOMMISSIONED 2025-09-30 and now returns 404.**
> The template's `GET /detects/queries/detects/v1` + `POST /detects/entities/summaries/GET/v1` calls
> are **dead** — do not use them. **[STALE]** Build entirely on the **Alerts API**:

1. `GET {base}/alerts/queries/alerts/v2?filter=<FQL>` → alert **`composite_id`s** in `resources[]`. (Alerts: Read)
2. `POST {base}/alerts/entities/alerts/v2` body `{"composite_ids":[…]}` → full alert objects. (Alerts: Read)
3. `PATCH {base}/alerts/entities/alerts/v3` → update status (new→in_progress→closed). (Alerts: Write)
   - Body uses `composite_ids` + an action-parameters payload — **confirm the exact body schema against
     the live Alerts Swagger before hardcoding** (it is not a bare `ids` array).
- Pagination beyond 10k: `POST {base}/alerts/combined/alerts/v1` with an `after` token.

## 4. Alert/detection data shape (triage input + Sigma fodder)

Field reference from the template's *legacy Detects* response. **[TEMPLATE]** Most fields carry over to
Alerts v2, but the top-level id is now `composite_id` (not `detection_id`) — **confirm field names
against a real Alerts v2 response** when wiring 0D.

- `device`: `hostname`, `device_id` (← the **AID**, key for containment), `local_ip`, `external_ip`,
  `os_version`, `platform_name`.
- each `behaviors[]` entry:
  - file: `sha256`, `md5`, `filename`, `filepath`, `cmdline`, `alleged_filetype`
  - identity: `user_name`, `user_id`
  - **MITRE**: `technique_id` (e.g. `T1003`), `technique`, `tactic`, `tactic_id`
  - scoring: `severity`, `confidence`, `scenario` (e.g. `NGAV`, `credential_theft`)
  - IOC: `ioc_type`, `ioc_value`, `ioc_source`, `ioc_description`
  - lineage: `parent_details.parent_sha256`, `parent_details.parent_cmdline`
  - `control_graph_id` (→ builds the Falcon UI detection link)
  - `pattern_disposition_details` (see §6 — our detect-only signal)
- detection-level: `max_severity_displayname` (Low/Medium/High/Critical), `quarantined_files[]`.

The template's sample is a **mimikatz credential-theft** detection (`T1003`, `scenario:
credential_theft`) — exactly the post-exploitation a honeypot attacker runs. `technique_id` flows
straight into the Qdrant MITRE RAG + Sigma generation (later phases).

## 5. Response action — Contain / Lift Containment (job responsibility #5) [CONFIRMED 2026-06-26]

Network-isolate (or release) a host by **device_id (AID)**:
- Contain: `POST {base}/devices/entities/devices-actions/v2?action_name=contain` body `{"ids":["<aid>"]}`
- Release: `POST {base}/devices/entities/devices-actions/v2?action_name=lift_containment` body `{"ids":["<aid>"]}`
- Scope **Hosts: Write**; **≤100 ids per call**. (Other actions: `hide_host`, `unhide_host`,
  `detection_suppress`/`_unsuppress`.) A contained host can still reach the Falcon cloud.
- **Resolve the AID first:** `GET {base}/devices/queries/devices/v1` (Hosts: Read) → `POST
  {base}/devices/entities/devices/v2` body `{"ids":[…]}` for full host details.
- In our SOAR this is the verifier-passed, high-severity, **human-gated** auto-response (spec §5.3).

## 6. Detect-only — a console PREVENTION-POLICY build, not an install flag [CONFIRMED 2026-06-26]

We run Falcon **detect-only** so the attack proceeds (full kill chain) while Falcon still detects.
This is **not** an install-time flag and **not a single toggle** — it is a prevention policy assigned
to the host's group **after** the sensor appears:
- **ML settings:** set each pair to **detection = MODERATE/AGGRESSIVE, prevention = DISABLED**
  (`cloud_anti_malware`, `sensor_anti_malware`, `adware_and_pup`, the `_user_initiated`/`_microsoft_office`
  variants). The vendor Terraform/Pulumi provider documents `detection=MODERATE`/`prevention=DISABLED`
  as a supported config.
- **Also turn OFF the separate boolean prevention switches** (exploit mitigation, ransomware,
  credential dumping, suspicious processes/scripts, lateral movement, `quarantineOnWrite`, …) — disabling
  the ML sliders alone does **not** yield a fully non-blocking sensor.
- **Keep detection/visibility toggles ON** (`detectOnWrite`, `engineFullVisibility`, `additionalUserModeData`).
- **Verify on a real detection:** each behaviour's `pattern_disposition_details` should be **all-false**
  (`process_blocked: false`, `quarantine_file: false`, `kill_process: false`, …) — that's the proof the
  policy is monitor-only.

## 7. Sensor install on Windows Server 2022 [CONFIRMED 2026-06-26]

- **Silent command:** `WindowsSensor.exe /install /quiet /norestart CID=<your-CID-with-2char-checksum>`.
  **No reboot** needed; runs fully non-interactively as SYSTEM.
  - **Plan 0B installs HANDS-ON via RDP** (user preference — see memory `feedback_prefers_hands_on_doing`);
    `az vm run-command` is a documented fallback, not the default.
- **Installer + CID:** console → **Host setup and management → Sensor downloads** (the **CCID with
  checksum** is on the right of that page). The download is **auth-gated** — no anonymous URL (a console
  session, or API creds with **Sensor Download: Read**, is required to fetch the binary).
- **Optional params:** `ProvToken=<token>` only if the tenant **requires** an install token (check
  *Sensor update policies*); `GROUPING_TAGS`, `ProvNoWait`, `NO_START`, `/log` as needed.
- **Egress:** sensor is **443-only** (TLS 1.2+) to `*.cloudsink.net` + a few `crowdstrike.com` FQDNs.
  Our existing NSG `allow-web` (TCP 80,443 → Internet) **already covers it — no NSG change needed.**

## 8. Near-real-time ingestion options (for 0D) [CONFIRMED 2026-06-26]

- **Tight poll** of the Alerts API (1–5 min), OR the **Event Streams datafeed** for near-real-time:
  `GET {base}/sensors/entities/datafeed/v2?appId=<label>` (Event streams: Read); refresh session via
  `POST {base}/sensors/entities/datafeed-actions/v1/<partition>?action_name=refresh_active_stream_session`.
- The template's **daily Schedule Trigger is far too slow** for a honeypot — replace it.

## 9. Honest caveats inherited from the template (do NOT copy blindly) [TEMPLATE]

- Its `/detects/*` calls are **dead** (§3), its base URL is **us-2-specific** (§2), and its **daily
  trigger** is too slow (§8) — all must change.
- **VT URL typo** (`{{ $json.dsha256 }}` → should be `sha256`).
- CrowdStrike/Jira/Slack nodes ship **disabled** with **pinned sample data** (safe-import) — re-enable +
  rebind credentials after import.
- `continueOnFail: true` on the VT nodes is a good **resilience** pattern to keep.

## 10. How this maps onto our plans

- **Plan 0B (Falcon):** start the trial → **enable Insight XDR** → create the API client (scopes in §1) →
  **install the sensor by hand via RDP** (§7) → build + assign a **detect-only prevention policy** (§6) →
  trigger a controlled test detection and verify `pattern_disposition_details` all-false → validate the
  **OAuth + Alerts read + Hosts read + Contain→Lift** round-trip (§5). Record the tenant **cloud/base URL**
  (§2) and **trial start/expiry**. No paid provisioning.
- **Plan 0D (n8n wiring):** fork the template as the **Falcon detections poll** skeleton — keep the OAuth
  credential, the split-per-behaviour iteration, and `continueOnFail` enrichment — but **rebuild the fetch
  on the Alerts API** (§3), pin **our** cloud base URL (§2), swap the daily trigger for a tight poll/stream
  (§8), and replace the Set→Jira→Slack tail with **Claude Opus triage + verifier gate + enrichment roster
  (GreyNoise/AbuseIPDB/VT/URLscan) + Qdrant + DFIR-Iris + Discord + Falcon `Contain` + run-log**. Fix the
  VT typo.
