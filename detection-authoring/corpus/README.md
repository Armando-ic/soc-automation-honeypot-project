# Frozen event corpus (Phase 2 gate tiers 3 and 4)

Events are JSON dicts using Sigma `process_creation` field names, which line up
1:1 with the honeypot's Sysmon fields (Splunk Add-on for Microsoft Sysmon).
Matching is case-insensitive (Sigma default).

## Field mapping (Splunk/Sysmon -> Sigma process_creation)
- `EventCode=1` -> `EventID: 1` (Sysmon Process Create)
- `Image`, `CommandLine`, `ParentImage`, `User` -> same names
- `host` (Splunk) is not a Sigma process_creation field and is omitted here.

## positives/
Reconstructed from the captured events documented in vault/detections/. Each
technique file is a list of >=1 event; a rule must fire on ALL of them (T3).

## benign/baseline.json
Normal process-creates a good rule must stay quiet on (T4), PLUS fair
near-misses: `cmd.exe /c ping 8.8.8.8` embeds a real IP literal, so a naive
"IP anywhere in a cmd.exe command line" rule for T1059.003 will false-positive
on it. That is intentional: it forces a tighter rule and, where a technique is
genuinely hard to detect FP-free, the gate reports it honestly. Nothing here is
an impossible trap; this file is the whole benign set the gate uses.
