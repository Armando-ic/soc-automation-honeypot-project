# Falcon detect-only prevention policy (Phase 0B) — config-as-docs

Goal: the sensor DETECTS the full attacker kill chain while letting it PROCEED
(no block/quarantine/kill), so the honeypot stays high-interaction. Verified by
`pattern_disposition_details` all-false on a real detection. Applied at Plan 0B Task 5.

Console path: Endpoint security → Configure → Prevention policies → (Windows) →
create `honeypot-detect-only` → assign to host group `hg-honeypot`.

## ML sliders — set DETECTION high, PREVENTION off
For EVERY ML setting pair set Detection = AGGRESSIVE (or MODERATE) and Prevention = DISABLED:
- Cloud Anti-malware            : Detection = AGGRESSIVE · Prevention = DISABLED
- Sensor Anti-malware           : Detection = AGGRESSIVE · Prevention = DISABLED
- Adware & PUP                  : Detection = AGGRESSIVE · Prevention = DISABLED
- Cloud Anti-malware (MS Office): Detection = AGGRESSIVE · Prevention = DISABLED
- Cloud AM (user-initiated)     : Detection = AGGRESSIVE · Prevention = DISABLED
- Sensor AM (user-initiated)    : Detection = AGGRESSIVE · Prevention = DISABLED

## Boolean PREVENTION switches — ALL OFF (disabling ML sliders alone is not enough)
Turn OFF every prevention/blocking toggle so nothing is blocked, e.g.:
- Quarantine on write ............ OFF
- Exploit mitigation (Force ASLR/DEP, SEH overwrite, Heap spray, NULL-page) OFF
- Ransomware (file encryption, file-system access, backup deletion) OFF
- Behavioral prevention: Suspicious Processes, Suspicious Scripts/Commands,
  Code Injection, Credential Dumping, Lateral Movement OFF
- Driver-based / FS containment blocking OFF

## Detection / VISIBILITY toggles — ON (so detections still fire & stream)
- Notify End Users ............... OFF (no honeypot-side popups)
- Additional User Mode Data ...... ON
- Detect on Write / Engine Full Visibility ... ON
- Sensor Tampering Protection .... (leave default; not a prevention-of-attack toggle)

## Verify (Task 6): a detection appears in the console AND each behaviour's
## `pattern_disposition_details` is all-false (process_blocked / quarantine_file /
## kill_process / etc. = false). If anything blocked, a Prevention toggle is still on.
