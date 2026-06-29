# CrowdStrike Falcon — honeypot setup walkthrough (Plan 0B)

A step-by-step record of standing up **CrowdStrike Falcon in detect-only mode** on the internet-exposed
Windows honeypot (`vm-honeypot-win`), with OAuth API access and a Contain/Lift capability. Written as
**proof-of-work** and a **rebuild/revisit reference**. Companion docs:
- [`crowdstrike-api-notes.md`](crowdstrike-api-notes.md) — API reference (auth, Alerts, Hosts/Contain endpoints).
- [`falcon-detect-only-policy.md`](falcon-detect-only-policy.md) — the prevention-policy toggle map (config-as-docs).
- [`falcon-validation.md`](falcon-validation.md) — empirical evidence (created at Task 6, pending).
- `scripts/falcon-contain-roundtrip.ps1` — the Contain→Lift validator (Task 7, pending).

**Why:** real EDR detections + a human-gated `Contain` auto-response feed the agentic-SOC loop (Plan 0D-2).
Detect-only keeps the honeypot **high-interaction** — Falcon *observes* the full attacker kill-chain but never
blocks/quarantines/kills.

**Environment (constants):**
| | |
|---|---|
| Honeypot VM | `vm-honeypot-win` · `rg-honeypot` · public `128.203.185.25` · private `10.66.0.4` · Windows Server 2022 |
| Tenant cloud | **us-2** · API base `https://api.us-2.crowdstrike.com` |
| API client | `honeypot-soar` (scopes: Alerts R/W, Hosts R/W, Event streams R) |
| Sensor | Falcon Windows sensor **7.38.21003.0** |
| Trial | activated ~2026-06-28, **expires 2026-07-13** (15-day); keep/drop checkpoint ~2026-07-12 |
| Secrets | Client ID/Secret + CID live ONLY in gitignored `Personal/honeypot-vm-creds.txt` — never committed/echoed |

---

## Step 1 — Start the 15-day trial
- `https://www.crowdstrike.com/products/trials/try-falcon/` → submit with a controlled email. Access email
  arrives ~24h later. Default tier = **Falcon Go** (NGAV only); real EDR is the free **Insight XDR** module
  added in Step 4.
- Activate, log into the console, note the "days remaining" banner (the trial clock).

## Step 2 — Create the OAuth API client
Console → **Support and resources → API clients and keys → Add new API client**:
- Name `honeypot-soar`, description "Plan 0B/0D honeypot SOAR — alerts read + host contain".
- Scopes: **Alerts** Read+Write · **Hosts** Read+Write · **Event streams** Read.
- On Create, the window shows **Client ID**, **Secret (once!)**, and the **Base URL** (= your cloud).
- **Copy the Secret immediately** into `Personal/honeypot-vm-creds.txt` (it's never shown again).
- Our Base URL = `https://api.us-2.crowdstrike.com` → cloud **us-2**.

> Scope rationale: Alerts R = poll detections (0D-2 trigger); Alerts W = update alert status; Hosts R =
> resolve the host AID; Hosts W = the Contain/Lift device action; Event streams R = the optional datafeed
> trigger. **Do NOT** pick the legacy "Detections" scope — that API is decommissioned (404 since 2025-09-30);
> we build on the **Alerts API**.

## Step 3 — Install the sensor (hands-on via RDP)
- Console → **Host setup and management → Sensor downloads** → download the latest **Windows** sensor
  (`WindowsSensor.<ver>.exe`). On the same page, **Copy your Customer ID (CID)** (CCID with checksum) →
  `Personal/honeypot-vm-creds.txt` under `## Falcon CID`. Check **Sensor update policies** for an installation
  token (trial tenants usually don't need one).
- RDP to `128.203.185.25` (user `analyst`). Get the installer onto the box (download in the VM's browser over
  443, or RDP clipboard). In an **elevated** shell:
  ```
  .\WindowsSensor.<ver>.exe /install /quiet /norestart CID=<CID-with-checksum>
  ```
  (add `ProvToken=<token>` only if Step 1 said it's required). No reboot needed.
- Verify the service: `sc query csagent` → `STATE : 4  RUNNING`.
- Console → **Host setup and management → Host management** → confirm the host appears. Ours:
  hostname **`vm-honeypot-win`**, sensor **7.38.21003.0**, external IP `128.203.185.25` (confirms it's the
  right box).

> **Egress:** the sensor is **443-only** to the Falcon cloud. The honeypot's existing `nsg-honeypot`
> `allow-web` rule (TCP 80/443 → Internet, priority 1020, ahead of the deny-all at 4096) already covers it —
> **no NSG change needed.** DNS is allowed by `allow-dns` (53).

## Step 4 — Enable Insight XDR (free EDR) + API smoke test
- Console menu → **CrowdStrike Store → CrowdStrike Apps → Falcon Insight XDR → Try it for free.** Activation
  takes **~30 min**. (Start this early — it has the longest wait.)
- Confirm EDR unlocked in-trial (not guaranteed by default, so verify):
  - Console → **Endpoint security → Monitor → Endpoint detections** shows EDR views (not just NGAV).
  - API smoke test (PowerShell; set `$env:CS_ID/$env:CS_SECRET/$env:CS_BASE` for the session only):
    ```powershell
    $b = @{ client_id=$env:CS_ID; client_secret=$env:CS_SECRET }
    $t = Invoke-RestMethod -Method Post -Uri "$env:CS_BASE/oauth2/token" -Body $b -ContentType "application/x-www-form-urlencoded"
    $h = @{ Authorization = "Bearer $($t.access_token)" }
    Invoke-RestMethod -Method Get -Uri "$env:CS_BASE/alerts/queries/alerts/v2?limit=1" -Headers $h
    ```
    Expect a token + HTTP 200 (empty `resources` is fine — no detections yet). A 403 = scope/Insight not
    active yet.

## Step 5 — Host group + detect-only prevention policy
- **Host group:** Host setup and management → **Host groups → Create group** → `hg-honeypot`, **Dynamic**,
  rule **Hostname equals `vm-honeypot-win`** (auto-re-includes after a snapshot rebuild). Must contain ONLY
  the honeypot.
- **Prevention policy:** Endpoint security → Configure → **Prevention policies → (Windows) → Create policy**
  → `honeypot-detect-only`. Set every toggle per [`falcon-detect-only-policy.md`](falcon-detect-only-policy.md):
  **detection/visibility ON, every prevention/blocking action OFF; ML Detection sliders = AGGRESSIVE,
  Prevention sliders = DISABLED.** Then **Enable** + **Assign to `hg-honeypot`**.
- **⚠️ Quarantine-dependency gotcha (real, hit on 2026-06-29):** enabling **"Script-based execution
  visibility"** pops a *"Confirm dependent setting"* dialog forcing **"Quarantine & security center
  registration" ON** — which enables Falcon's quarantine subsystem + registers it as the Windows AV. That's
  prevention, not detect-only. **Cancel the dialog; leave that toggle OFF; skip any visibility toggle that
  depends on it.**
- **Behavioral detection enrichments worth turning UP** (pure detection, no blocking): *Cloud-based anomalous
  process execution* → Detection AGGRESSIVE ⭐, *Extended user mode data visibility* → Detection AGGRESSIVE,
  *Retrospective detections* → ON. (The honeypot's real traffic is behavioral — RDP brute-force + post-auth —
  so these matter most.)
- **Assignment propagation:** the Policy-assignment tab shows **Applied / Pending** counts. Right after
  assigning it read **Applied 0 / Pending 1** (precedence 3) — *Pending 1 is correct*: the policy is assigned
  and winning precedence; it flips to **Applied 1** on the sensor's next heartbeat (a few minutes). Verify
  Applied=1 before testing.

## Step 6 — Verify detect-only *(PENDING — resume here)*
Trigger a controlled detection and prove nothing was blocked:
- On the honeypot (elevated PowerShell), write the EICAR test string (assembled in two parts so this file
  doesn't trip AV):
  ```powershell
  $p1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}'
  $p2 = '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  Set-Content -Path "$env:TEMP\eicar.com" -Value ($p1 + $p2) -Encoding Ascii
  ```
  (Defender real-time was disabled in Plan 0A, so only Falcon reacts.) Or wait for a real attacker detection
  (the gold standard — the box is internet-exposed).
- Console: the detection appears in **Endpoint security → Monitor → Endpoint detections**, **not blocked**;
  the `eicar.com` file still exists.
- API: pull it and check disposition:
  ```powershell
  $ids = (Invoke-RestMethod -Method Get -Headers $h -Uri "$env:CS_BASE/alerts/queries/alerts/v2?limit=10").resources
  $body = @{ composite_ids = $ids } | ConvertTo-Json
  $alerts = Invoke-RestMethod -Method Post -Headers $h -Uri "$env:CS_BASE/alerts/entities/alerts/v2" -Body $body -ContentType "application/json"
  $alerts.resources | Select-Object composite_id, filename, pattern_disposition_details | ConvertTo-Json -Depth 6
  ```
  **Detect-only confirmed when `pattern_disposition_details` is all-false** (`process_blocked:false`,
  `quarantine_file:false`, `kill_process:false`, …). Capture the redacted JSON into `falcon-validation.md`.

## Step 7 — Contain → Lift round-trip *(PENDING)*
Run `scripts/falcon-contain-roundtrip.ps1 -Hostname 'vm-honeypot-win'` (creds via `CS_ID/CS_SECRET/CS_BASE`
env). It resolves the AID, calls Contain (`POST /devices/entities/devices-actions/v2?action_name=contain`),
polls status → `contained`, then Lift (`action_name=lift_containment`) → `normal`. Cross-check in Host
management. (While contained, the honeypot's Splunk egress pauses; the UF queues + backfills on lift.)
Capture the AID + status transitions in `falcon-validation.md`.

## Step 8 — Lifecycle + trial-end *(PENDING)*
Add the Falcon lifecycle/off-board/rebuild-re-register section to `RUNBOOK.md` and the trial keep/drop
checkpoint (~2026-07-12). At trial end: DROP (default) = uninstall sensor + revoke API client ($0 ongoing,
evidence already captured); KEEP NGAV = Falcon Go ~$60/dev/yr; KEEP EDR = Falcon Enterprise ~$185/dev/yr.

---

## Lessons / gotchas captured
1. **Quarantine dependency** — see Step 5. Several visibility toggles silently require the quarantine
   subsystem; for detect-only, skip them rather than enable quarantine.
2. **Pending ≠ broken** — a freshly assigned policy reads `Applied 0 / Pending 1`; that's normal propagation,
   it flips on the next sensor heartbeat. Only worry if it's still Pending after ~10–15 min (then check
   `sc query csagent` + Last Seen for a check-in problem).
3. **Legacy Detections API is dead** (404 since 2025-09-30) — build on the **Alerts API** (`/alerts/queries`
   + `/alerts/entities`). Don't select the legacy Detections scope.
4. **Tenant cloud must be read, not assumed** — ours is **us-2**; the API base is per-cloud and hardcoded for
   raw HTTP.
5. **One tenant, one purpose** — a personal machine briefly auto-enrolled in the trial tenant; it was
   **uninstalled** (maintenance token → `WindowsSensor.exe /uninstall /quiet MAINTENANCE_TOKEN=<token>`) so
   the tenant is honeypot-only. Critical: a tenant-wide alert poll (0D-2) would otherwise sweep a personal
   PC's alerts into the SOC loop — and could queue your own machine for Contain.
6. **Detect-only ≠ turn everything off** — turning a *prevention* toggle off does not suppress the detection;
   CrowdStrike still raises the alert, it just doesn't act. So max the detection sliders, zero the prevention.
