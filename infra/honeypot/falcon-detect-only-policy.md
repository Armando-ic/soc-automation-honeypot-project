# Falcon detect-only prevention policy (Phase 0B) — config-as-docs

Goal: the sensor DETECTS the full attacker kill chain while letting it PROCEED
(no block/quarantine/kill), so the honeypot stays high-interaction. Verified by
`pattern_disposition_details` all-false on a real detection (Plan 0B Task 6).

**Status:** policy `honeypot-detect-only` BUILT + assigned to `hg-honeypot` on **2026-06-29**, confirmed
**Applied: 1** (Date applied 2026-06-28 23:57:53; host Last seen 2026-06-29). Detect-only **VALIDATED**
2026-06-29 — a real EDR detection (Execution/User Execution T1204, Informational, `Source: Falcon Insight`)
returned `pattern_disposition: 0` with all 28 `pattern_disposition_details` booleans `false`.
Evidence: [`falcon-validation.md`](falcon-validation.md).

> Reconciled to the **actual** Falcon console (us-2 tenant, Windows prevention policy, sensor 7.38.21003.0)
> on 2026-06-29 — the section names below match the live UI, which is more granular than the original spec.
> The narrative step-by-step is in [`falcon-setup-walkthrough.md`](falcon-setup-walkthrough.md).

Console path: Endpoint security → Configure → Prevention policies → (Windows) →
`honeypot-detect-only` → assign to host group `hg-honeypot`.

## The one-line principle
**Detection/visibility ON, every prevention/blocking action OFF.** Turning a *prevention* toggle off does
NOT suppress the detection — CrowdStrike still raises the alert; the toggle only controls whether the sensor
*acts* (blocks/kills/quarantines). So we max detection and zero out enforcement.

## ⚠️ Detect-only gotcha — the quarantine dependency (found 2026-06-29)
Enabling **"Script-based execution visibility"** (and potentially other visibility toggles) forces
**"Quarantine & security center registration" ON** via a "Confirm dependent setting" dialog. That master
toggle turns on Falcon's **quarantine subsystem** AND registers Falcon as the Windows AV provider — the
opposite of a detect-only honeypot. **Decision: Cancel that dialog; leave "Quarantine & security center
registration" OFF and skip any visibility toggle that depends on it.** The pure-detection enrichments below
have no such dependency and are the higher-value ones anyway.

## NGAV machine-learning sliders — Detection AGGRESSIVE, Prevention DISABLED
(Console sections: *Next-gen antivirus | Cloud machine learning*, *| Sensor machine learning*,
*| Microsoft Office file macro machine learning*.)
- Cloud-based anti-malware ............... Detection = AGGRESSIVE · Prevention = DISABLED
- Cloud-based adware & pup ............... Detection = AGGRESSIVE · Prevention = DISABLED
- Sensor-based anti-malware .............. Detection = AGGRESSIVE · Prevention = DISABLED
- Cloud anti-malware for MS Office files . Detection = AGGRESSIVE (optional) · Prevention = DISABLED
- On-demand-scan ML sliders .............. leave DISABLED (real-time *Detect on write* covers us)

## Behavioral DETECTION enrichments — turn UP (pure detection, no blocking, no quarantine dependency)
These were OFF by default and are the most valuable detections for a behavioral honeypot:
- **Cloud-based anomalous process execution** (*Cloud-based detections | Behavioral detections*) → Detection = **AGGRESSIVE** ⭐
- **Extended user mode data visibility** (*Sensor visibility | Enhanced visibility*, slider) → Detection = **AGGRESSIVE**
- **Retrospective detections** (*Cloud-based detections | Behavioral detections*) → **ON**

## Visibility / detection toggles — ON
- Additional user mode data visibility ... ON
- Detect on write ........................ ON
- Redacted HTTP detection details ........ ON (default)
- (Optional, *only if no quarantine dependency fires*) Interpreter-only visibility, HTTP visibility and
  detection, Enhanced exploitation visibility, Enhanced DLL load visibility, Memory scanning with CPU → ON
- Notify "End user notifications" ........ OFF (no honeypot-side popups)

## Prevention / blocking — ALL OFF (this is what makes it detect-only)
Confirmed all-off across every section on 2026-06-29:
- **Next-gen antivirus | On write:** Quarantine on write — OFF
- **Next-gen antivirus | Quarantine:** Quarantine & security center registration — OFF · Quarantine on removable media — OFF
- **Next-gen antivirus | Clean infected MS Office files:** MS Office malicious macro removal — OFF
- **Malware protection | Execution blocking:** Custom indicator blocking, Suspicious process prevention,
  Suspicious registry operation prevention, Boot configuration database protection, Suspicious script and
  command prevention, Intelligence-sourced threat prevention, Driver load prevention, Vulnerable driver
  protection, File system containment — ALL OFF
- **Behavior-based prevention | Exploit mitigation:** ASLR bypass, DEP bypass, Heap spray pre-allocation,
  NULL page allocation, SEH overwrite prevention — ALL OFF
- **Behavior-based prevention | Ransomware:** Backup deletion, Cryptowall, File encryption, Locky, File
  system access prevention, Volume shadow copy (audit/protect) — ALL OFF
- **Behavior-based prevention | Exploitation behavior:** Application exploitation, Chopper webshell,
  Drive-by download, Code injection, JavaScript execution via Rundll32 prevention — ALL OFF
- **Behavior-based prevention | Lateral movement and credential access:** Windows logon bypass ("Sticky
  keys"), Credential dumping prevention — ALL OFF
- **Behavior-based prevention | Remediation:** Advanced remediation — OFF
- **Sensor capabilities:** Sensor tamper prevention — OFF (fine for a sensor we manage)
- Every ML **Prevention** slider — DISABLED

## Host group
`hg-honeypot` — **Dynamic**, rule Hostname equals `vm-honeypot-win` (auto-re-includes after a snapshot
rebuild). Must contain ONLY the honeypot (the personal PC was uninstalled 2026-06-29 to keep the tenant
honeypot-only).

## Verify (Task 6 — NOT yet done)
Trigger a detection (EICAR or a real attacker hit) → confirm in *Endpoint security → Monitor → Endpoint
detections* it was detected but NOT quarantined (the EICAR file still exists) → pull it via the Alerts API
and confirm each behaviour's `pattern_disposition_details` is **all-false** (`process_blocked`,
`quarantine_file`, `kill_process`, … = false). If anything blocked, a Prevention toggle is still on.
