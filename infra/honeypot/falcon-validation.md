# Falcon validation — empirical proof-of-work (Phase 0B)

Captured evidence that the `honeypot-detect-only` posture behaves as designed: Falcon **detects** activity
on the internet-exposed honeypot but **takes no action** (no block / quarantine / kill / contain). Companion
docs: [`falcon-setup-walkthrough.md`](falcon-setup-walkthrough.md) (narrative steps),
[`falcon-detect-only-policy.md`](falcon-detect-only-policy.md) (the toggle map),
[`crowdstrike-api-notes.md`](crowdstrike-api-notes.md) (API reference).

**Environment (constants):** `vm-honeypot-win` · `rg-honeypot` · public `128.203.185.25` · Windows Server
2022 · tenant cloud **us-2** (`https://api.us-2.crowdstrike.com`) · sensor **7.38.21003.0** · policy
`honeypot-detect-only` applied (precedence 3). Secrets (Client ID/Secret, CID) live ONLY in gitignored
`Personal/honeypot-vm-creds.txt` — never committed/echoed. `composite_id` is redacted below because it embeds
the CID.

---

## Task 5 confirmation — policy applied (2026-06-29)
Verified on the host's **Policies applied to vm-honeypot-win** pane:
- **Prevention policy:** `honeypot-detect-only`
- **Date applied:** 2026-06-28 23:57:53 (no longer Pending — the policy landed on the host)
- **Last seen:** 2026-06-29 10:54:28 (sensor checking in)

`Applied: 1`. Gate cleared for detection testing.

## Task 6 — detect-only validation (2026-06-29) ✅

### Method
- **Trigger (host-side, RDP, elevated PowerShell):** wrote the EICAR test string to disk on the honeypot:
  ```powershell
  $p1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}'
  $p2 = '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  Set-Content -Path "$env:TEMP\eicar.com" -Value ($p1 + $p2) -Encoding Ascii
  ```
- **Pull (local trusted machine, NOT the honeypot):** OAuth token → `GET /alerts/queries/alerts/v2` →
  `POST /alerts/entities/alerts/v2`. The API secret was deliberately kept **off** the honeypot (the box is the
  attack surface; the `honeypot-soar` client holds `Hosts:Write` = tenant-wide `Contain`).

### Key finding — EICAR surfaced as a *behavioral* detection, not a signature file-detection
Falcon is ML/behavioral; EICAR is a *signature-AV* test artifact (a benign, inert 68-byte file). Writing it
produced **no malware/file detection** — instead Falcon's behavioral engine (the *Cloud-based anomalous
process execution* enrichment, set to Aggressive) convicted the **PowerShell process** that wrote it and
raised an **Informational** Execution detection. So "EICAR didn't trip the AV" is expected and correct; the
real proof is what the sensor *did about it*: nothing.

### Host-side proof — file survived (not quarantined)
```
FullName                                          Length
--------                                          ------
C:\Users\analyst\AppData\Local\Temp\2\eicar.com  70
```
The `eicar.com` file still existed after the detection fired → `quarantine_file` did not act.

### API proof — the detection + its disposition
Endpoint detection list: **1 result**, `Source product: Falcon Insight` (EDR module, not just NGAV).

```json
{
  "composite_id":        "<redacted — embeds CID>",
  "created":             "2026-06-29T15:11:34.51235084Z",
  "severity":            10,
  "severity_name":       "Informational",
  "tactic":              "Execution",
  "technique":           "User Execution",
  "technique_id":        "T1204",
  "filename":            "powershell.exe",
  "cmdline":             "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ",
  "pattern_disposition": 0
}
```

`pattern_disposition: 0` (the summary integer = no action flags set). Decoded into the full boolean
breakdown — **all 28 false**:

```json
{
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled":         false,
  "containment_file_system":          false,
  "critical_process_disabled":        false,
  "detect":                           false,
  "fs_operation_blocked":             false,
  "handle_operation_downgraded":      false,
  "inddet_mask":                      false,
  "indicator":                        false,
  "kill_action_failed":               false,
  "kill_parent":                      false,
  "kill_process":                     false,
  "kill_subprocess":                  false,
  "mfa_required":                     false,
  "operation_blocked":                false,
  "policy_disabled":                  false,
  "prevention_provisioning_enabled":  false,
  "process_blocked":                  false,
  "quarantine_file":                  false,
  "quarantine_machine":               false,
  "registry_operation_blocked":       false,
  "response_action_already_applied":  false,
  "response_action_failed":           false,
  "response_action_triggered":        false,
  "rooting":                          false,
  "sensor_only":                      false,
  "suspend_parent":                   false,
  "suspend_process":                  false
}
```

### Verdict
**Detect-only confirmed.** Every prevention/response flag is `false` — `process_blocked`, `quarantine_file`,
`quarantine_machine`, `kill_process`, `operation_blocked`, `containment_file_system` all `false`. The sensor
raised an EDR detection (queryable via the Alerts API, the same path Plan 0D-2 will poll) while leaving the
host untouched. The honeypot stays high-interaction.

> **Field facts for 0D-2 (carry-forward):** detection trigger = `pattern_disposition == 0` (or
> `pattern_disposition_details` all-false) marks a pure observation; `Source product` = `Falcon Insight`
> identifies EDR-origin alerts; `composite_id` embeds the CID (redact in any committed artifact/log); the
> behavioral enrichments — not signatures — are what convict on this box, matching its real attacker traffic
> (RDP brute-force + post-auth behavior).

## Task 7 — Contain → Lift round-trip (2026-06-29) ✅
Ran `scripts/falcon-contain-roundtrip.ps1 -Hostname vm-honeypot-win` from a **local** machine (creds via
`CS_ID/CS_SECRET/CS_BASE` env, base us-2). The script resolved the AID by hostname, called `Contain`, polled
to `contained`, then `Lift`, polled to `normal`:

```
AID = 9134…5865 · status = normal          (resolved by hostname:'vm-honeypot-win')
Contain requested. Polling...
  status = contained                        ← network isolation confirmed (POST /devices/entities/devices-actions/v2?action_name=contain)
Lift requested. Polling...
  status = normal                           ← restored (action_name=lift_containment)
Round-trip complete. Final status = normal
```
(AID redacted to first/last 4 — it's a device identifier, not a credential.) Endpoints exercised:
`GET /devices/queries/devices/v1?filter=hostname:'…'` (resolve), `POST /devices/entities/devices-actions/v2`
(contain + lift), `POST /devices/entities/devices/v2` (status poll). While contained, the honeypot's egress
(incl. Splunk telemetry + RDP) is cut except the Falcon cloud channel; the UF queues + backfills on lift.

**Verdict:** the human-gated `Contain`/`Lift` response that Plan 0D-2 will graft onto the SOAR loop works
end-to-end via OAuth. **0B done-when met:** detect-only sensor ✓ + OAuth API ✓ + `Contain`→`Lift` ✓.

## Security note — API secret rotated (2026-06-29)
The `honeypot-soar` Client ID + Secret were accidentally pasted in plaintext during Task 7 setup. Per policy
(SaaS creds → rotate immediately) the secret was **reset in the Falcon console** (API clients and keys →
`honeypot-soar` → Reset secret) — same Client ID, new secret — and `Personal/honeypot-vm-creds.txt` updated;
the exposed value is now dead. **Lesson reinforced:** the API pull/Contain commands must run from a local
trusted machine, and secret values should be loaded from the gitignored creds file, never typed/pasted inline
(a `$env:CS_SECRET = '<value>'` line lands in PSReadline history on disk and in any chat transcript).
