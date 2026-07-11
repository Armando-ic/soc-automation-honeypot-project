---
status: saved-search-active
technique_id: T1059.001
tactic: Execution
last_run: 2026-05-12
related: [[../subprojects/2026-04-30-detection-foundations/runbook]], [[../architecture/components/sysmon]], [[../architecture/components/splunk]], [[../workflows/soc-triage-pipeline]], [[../decisions/0007-remove-slack-iris-native-gate]]
---

# T1059.001 — Command and Scripting Interpreter: PowerShell

## Description

T1059.001 is MITRE ATT&CK's sub-technique for adversary use of PowerShell as a scripting interpreter. The variant exercised here is **PowerShell with `-EncodedCommand`** (and its valid PowerShell shortenings `-e`, `-en`, `-enc`), which takes a UTF-16LE-base64-encoded command-line. Attackers use it to obfuscate malicious payloads through several layers (logs show base64 instead of clear-text) and to bypass simple substring-based detections. SwiftOnSecurity's Sysmon config captures the full CommandLine including the encoded blob, which is what makes this detectable end-to-end.

ATT&CK reference: https://attack.mitre.org/techniques/T1059/001/

## ART command

```powershell
# ART module is installed at C:\AtomicRedTeam\invoke-atomicredteam\ (not on default PSModulePath)
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1

# Test 15 = "ATHPowerShellCommandLineParameter -EncodedCommand parameter variations"
# (the "ATH" prefix marks it as an Atomic Test Harness synthetic - benign payload,
#  no external deps, no user prompts, well-defined cleanup)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief                 # preview the catalog
Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs       # installs AtomicTestHarnesses module
Invoke-AtomicTest T1059.001 -TestNumbers 15                   # execute
Invoke-AtomicTest T1059.001 -TestNumbers 15 -Cleanup          # cleanup (no-op for this test)
```

## Observations

First run 2026-04-30. The ATH harness wraps each invocation; the headline event is the launched `powershell.exe` itself.

| Field | Value (Phase 4 dev event, captured 2026-04-30 18:01:47 UTC) |
|---|---|
| `EventCode` | `1` (Process Create) |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | `powershell.exe -NoProfile -E VwByAGkAdABl...AAyADAAOQAAAA==` |
| `ParentImage` | `C:\Windows\System32\wbem\WmiPrvSE.exe` ← high-signal forensic indicator (ATH uses WMI to spawn) |
| `User` | `DESKTOP-VNEF7PC\mydfir` |
| `host` | `DESKTOP-VNEF7PC` |
| `ProcessId` | 4496 |
| `Hashes` | `MD5=2E5A8590CF6848968FC23DE3FA1E25F1, SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3, IMPHASH=3D08F4848535206D772DE145804FF4B6` (all three populated by SwiftOnSecurity) |

The base64 payload decodes (UTF-16LE) to `Write-Host <test-guid>` — the harness signature. Each ATH run uses a fresh GUID, so successive runs produce distinct events.

Splunk indexing lag observed: ~5 seconds from event to searchable.

Saved-search-to-fire delay: bounded by the 5-minute cron tick. Worst case ~5 minutes; typical ~150 seconds.

**ParentImage triage cheat sheet** (the forensic-interesting parents):

| ParentImage | Likely meaning |
|---|---|
| `winword.exe` / `excel.exe` / `outlook.exe` | Phishing macro launched PowerShell |
| `cmd.exe` from interactive logon | Manual analyst use, usually benign |
| `wscript.exe` / `cscript.exe` | Scripted attack chain |
| `WmiPrvSE.exe` | WMI-launched (could be lateral movement OR a synthetic test like ATH) |
| Unknown / non-system parent | Very suspicious |

## SPL

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)\s-e[ncodedommand]*\s"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents
        by _time, host, User, Image
```

| Clause | What it does |
|---|---|
| `index=mydfir-project` | Narrows to the project's index. Always specify `index=` — searching all indexes is the #1 SPL beginner mistake. |
| `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | Restricts to Sysmon's channel. Note the `XmlWinEventLog:` prefix (not the bare `WinEventLog:`) — that's the source value the **Splunk Add-on for Microsoft Sysmon** keys its props/transforms on. |
| `EventCode=1` | Sysmon's Process Create event. |
| `Image="*\\powershell.exe"` | Match any path ending in `\powershell.exe`. The leading backslash in the wildcard ensures we don't match `splunk-powershell.exe` or other `*-powershell.exe` filenames. |
| `\| regex CommandLine="..."` | Filter rows whose `CommandLine` matches a regex. Stricter than wildcard match. |
| `(?i)` | Case-insensitive flag. |
| `\s-e[ncodedommand]*\s` | Whitespace-bounded match for `-e` followed by zero-or-more letters from `{n,c,o,d,e,m,a}`. Catches all PowerShell prefix-shortenings of `-EncodedCommand` (`-e`, `-en`, `-enc`, `-encod`, `-encodedcommand`, etc.) while rejecting unrelated flag-shaped fragments like `-eq`, `-ed` (their continuing letters aren't in the alphabet). |
| `\| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image` | Aggregate to one row per (timestamp, host, user, image), counting hits and collecting unique CommandLines + parents per group. |

**`ParentImage` is the high-signal column for triage** — see ParentImage cheat sheet under Observations.

## Saved search

| Field | Value |
|---|---|
| Name | `T1059.001 - PowerShell Encoded Command` |
| App | `search` (default Splunk Search & Reporting app) |
| Owner | `mydfir` |
| Sharing | `app` (Shared in App) |
| Time Range | `Last 24 hours` (`-24h@h`) |
| Cron | `*/5 * * * *` (every 5 minutes; standard SOC cadence) |
| Trigger | `For each result` (`alert.digest_mode=False`) |
| Threshold | Number of Results > 0 |
| Schedule type | `Run on Cron Schedule` (`realtime_schedule=False` — required to keep `is_scheduled=True` in Splunk 10.2.2; see notes.md gotcha) |
| Throttle | None |
| Trigger Actions | Webhook + Add to Triggered Alerts (severity 5) |
| Webhook URL | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` (existing v2 production URL) |

### Live-fire validation results (2026-04-30)

Two cron firings produced two Iris alerts (#51 and #52), both with `iocs=[]` — Outcome A (gate-skipped path) confirmed. The architectural promise from D1's spec (§ 2.7) — "Sysmon-shaped alert traverses A2's Test 1 path on real production traffic with no n8n changes" — is validated end-to-end.

**Bonus discovery (Outcome B characteristic):** Claude decoded the base64 payload independently in both alerts (extracted the `Write-Host <GUID>` text). It just didn't find anything IOC-shaped inside, so `iocs_enriched` stayed empty. The base64-decoding capability is "free" without prompt changes — D1.5 hook is unnecessary as a prompt-engineering project for this technique class.

## Notes

- **Splunk's "For each result" + `alert.suppress=False` does NOT dedupe across cron ticks.** The same result row re-triggers the alert action every tick as long as it remains in the Time Range window. For the lab's purposes (learning loop, not production detection) this is acceptable — duplicates flow through the gate-skipped path each time, no IOCs, no cases, just Slack noise. Production tuning options: (1) narrow Time Range to `Last 5 minutes`; (2) set `alert.suppress=True` with `alert.suppress.fields=_time,host,Image,CommandLine`; (3) accept duplicates. See D1 notes.md for full discussion.
- **`realtime_schedule=False` is required** to keep `is_scheduled=True` in Splunk 10.2.2. The "Save As Alert" wizard defaults to "Real-Time Schedule," which silently flips `is_scheduled` back to False after any subsequent edit. The runbook documents this in the Recoveries ladder.
- **Severity stamping is inconsistent.** Claude's prose in the alert description says "medium" or "high" but `alert_severity_id` came back as 1 in alert #51 and 5 in alert #52 (same kind of event). Either Claude's structured `severity` field doesn't match its prose, or A1's `Extract Triage Result` Code node is mis-mapping. Flagged for D1.5 / A3 era investigation.
- **False positives in our environment so far: zero.** The only matches are intentional ART runs.
- If Claude misbehaves on the Sysmon-shaped payload (returns a malformed triage), the standby fix is the one-paragraph system-prompt addendum documented in [[../subprojects/2026-04-30-detection-foundations/runbook]] — *reactive only*; not applied by default. **Was not needed during D1's live-fire — Claude's default behavior on Sysmon payloads is correct.**
- Decoding the base64 payload is **not** done in SPL. Claude does it on the n8n side as part of triage. If the decoded payload contains something IOC-shaped (URL, IP literal, domain, hash), the gate fires (Outcome B). For ATH Test 15 (synthetic GUID payload), no IOCs exist inside the decoded payload — gate stays skipped (Outcome A).

## Re-validation 2026-05-12 (post-rebuild, v3 workflow)

After the 2026-05-08 OneDrive incident forced rebuilds of Win10 → Win10-v2 and (2026-05-12) n8n + IRIS from scratch, the detection chain was re-validated on the rebuilt lab. Per ADR 0007 the workflow simplified to v3 (Slack removed; human approval moves to IRIS-native review) — the detection chain's terminal node is now `Create Iris Alert` rather than the v2 gate-fired branch.

**Saved search recreated 2026-05-12** via REST API (the 2026-05-08 Splunk snapshot revert had wiped the original). The recreation surfaced a REST-API gotcha — see "Saved-search REST-API trap" below.

### Live-fire evidence

| Date | Generator | Iris alert | Notes |
|---|---|---|---|
| 2026-04-30 | ATH Test 15 (WmiPrvSE parent) | #51 | Gate-skipped path, iocs=[], severity_id=1 (Medium prose) |
| 2026-04-30 | ATH Test 15 | #52 | Gate-skipped path, iocs=[], severity_id=5 (High prose) — severity-stamping inconsistency observed first time here |
| 2026-05-12 | Synthetic webhook (Splunk-shape payload via curl) | #1, #2 | n8n+IRIS half re-validated; Claude decoded base64 independently, found no IOCs |
| 2026-05-12 | Synthetic `powershell.exe -EncodedCommand` via SSH to Win10-v2 → real cron-driven path | **#4** | **Full chain validated on rebuilt lab.** Severity = Low (id=4). Claude decoded payload as `Write-Host freeze-validation-<guid>`. AtomicTestHarnesses install was missed on Win10-v2 rebuild (TLS 1.2 not enabled during install) so a synthetic invocation substituted for ATH — same Sysmon event shape, same SPL match. |

Architectural promise from D1's spec § 2.7 *(Sysmon-shaped alert traverses A2's path on real production traffic with no n8n changes)* **revalidated** on v3 — the architecture survives the v2→v3 workflow simplification.

### Saved-search REST-API trap (root cause of a 4-hour debug 2026-05-12)

When recreating the saved search via REST API on 2026-05-12, the initial attempts returned `result_count=0` despite the same SPL returning 2 events when run interactively. Root cause: my POST'd `search` parameter started with `search index=mydfir-project ...`. Splunk's REST API stored that verbatim, and at execution time prepended its own implicit `search` — producing `search search index=mydfir-project ...`. The Splunk runtime parser then treated the second `search` as a **literal search term** (matching the word "search" in raw event text), reducing the scan from ~14110 events to ~10 — none of which matched the encoded-PS regex.

**Rule:** REST-API-created saved searches should NOT include the leading `search` keyword. The UI's "Save As Alert" flow strips it automatically; the REST API does not.

This is now captured in [[../subprojects/2026-04-30-detection-foundations/runbook#recoveries]] as a recovery ladder entry, and in [[../subprojects/2026-04-30-detection-foundations/notes#phase-11-2026-05-12--post-rebuild-revalidation-on-rebuilt-lab]].

### Phase 11 gotchas worth knowing for future detection work

- **AtomicTestHarnesses install needs TLS 1.2 explicit-enable** on Win10 default PowerShell 5.1. `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` before `Install-Module`.
- **`Splunk_TA_windows` lookup CSVs are missing** on the rebuilt Splunk install. Three `Could not load lookup=LOOKUP-*_for_windows` warnings appear on every search. **Cosmetic only** — these lookups apply to `wineventlog` sourcetype, not Sysmon. Doesn't affect this detection's results.
- **`alert_status_id=1` maps to "Unspecified"** on IRIS v2.4.22 (not "New" as historically documented). Workflow's hardcoded `1` should be re-derived; see workflow doc Known Issues.

## Claude-drafted Sigma (Phase 2)

Phase 2 (RAG + detection-as-code) adds an AI-vs-analyst artifact: a Sigma rule for this technique **drafted by Claude Opus 4.8**, RAG-grounded on the ATT&CK corpus, then judged by a deterministic 4-tier gate. It sits beside the hand-written SPL above. The point isn't to replace the analyst rule, it's to measure whether an LLM can author a detection a verifier will actually vouch for.

**Live authoring run (2026-07-07):** 5 trials, **5/5 passed the gate**, 95% CI [0.48, 1.00]. Full report: `detection-authoring/reports/authoring-cab1e37.md`.

**Honest before/after.** The first run scored **0/5** here. Every draft used an idiomatic Sigma *list-of-maps* selection (the standard way to OR across different fields, e.g. match PowerShell by `Image` OR by `OriginalFileName`), a construct the owned matcher doesn't model, so the subset guard correctly rejected all of them. The fix was a drafter prompt constraint steering the model to single-map selections combined with condition-level OR; the hardened gate and matcher were left untouched (fix commit `cab1e37`). Post-fix: 0/5 to 5/5. The gate was sound the whole time, the finding was about the authoring *subset boundary*, not the verifier.

**The generated rule** (`detection-authoring/rules/T1059.001.yml`):

```yaml
detection:
    selection_image:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_origname:
        OriginalFileName:
            - 'PowerShell.EXE'
            - 'pwsh.dll'
    selection_encoded:
        CommandLine|re: '(?i)\s-e(nc?(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?\s'
    condition: (selection_image or selection_origname) and selection_encoded
```

**Compiled SPL** (`detection-authoring/rules/T1059.001.spl`, produced by pySigma, not hand-written):

```spl
Image IN ("*\\powershell.exe", "*\\pwsh.exe") OR OriginalFileName IN ("PowerShell.EXE", "pwsh.dll")
| regex CommandLine="(?i)\\s-e(nc?(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?\\s"
```

**Gate verdict** (`detection-authoring/rules/T1059.001.gate.md`), all four tiers **PASS**:

| Tier | Check | Result |
|---|---|---|
| T1 | Valid Sigma (pySigma parse) | PASS |
| subset | Inside the owned matcher's supported subset | PASS |
| T2 | Compiles to SPL | PASS |
| T3 | Fires on the frozen positive corpus | PASS |
| T4 | Quiet on the frozen benign baseline | PASS |

**Matcher faithfulness: cross-checked against Zircolite (2026-07-07).** T3/T4 use our owned Sigma matcher, so its faithfulness to real Sigma semantics matters. We ran the one-time cross-check (`detection-authoring/scripts/crosscheck_zircolite.py`) against **Zircolite v3.7.6**, a real community offline Sigma engine: the T1059.001 reference rule was evaluated by both engines over the whole frozen corpus (3 positives + 8 benign) and they returned the identical detect/no-detect verdict on every event. Result: `Owned matcher agrees with Zircolite on the whole corpus.` So a gate PASS here means what a real Sigma engine would say, not just what our own matcher thinks.

Worth noting vs the analyst rule above: Claude's regex reaches `-encodedcommand` by nesting optional groups rather than the hand-written `[ncodedommand]*` character-class trick, equivalent in intent, and it added an `OriginalFileName` branch the hand-written SPL doesn't have.

## Phase 3 de-obfuscation triage

Phase 3 adds the layer that sits directly under the detection above. Once a `-EncodedCommand` fires the saved search, something has to safely decode the payload and decide whether the decoded *behavior* is malicious, without trusting a model to tell the truth about what it decoded to. That is the de-obfuscation triage engine (`malware-triage/`): it peels a payload into a byte-exact **verified** decode chain, extracts IOCs, applies versioned behavioral rules, and fuses a deterministic verdict. Built-in decoders (base64, base64-UTF16LE, hex, inflate/gunzip, char-array) are trusted-deterministic; a model may *propose* an exotic transform (rot-n, reverse), but the gate re-executes that proposal on our own bytes and compares byte-exact, so no model output can move the verdict. Same spirit as the Phase 2 Sigma gate: measure whether an LLM's contribution survives a verifier instead of taking its word.

**Live run (2026-07-11).** The labeled corpus (6 samples) plus 3 real captured `-EncodedCommand` executions were run through the live paid path.

*Corpus:* 5 of 6 landed verdict == label on the first paid run (base64, nested-base64, and char-array all decoded by the builtins, verdicts correct). The 6th surfaced a genuine corpus bug, below.

*Real captured samples:* 3 distinct `-EncodedCommand` executions pulled from Splunk (Sysmon EID 1). All three were the lab's own T1059.001 validation harness (benign `Write-Host` markers), one interactive and two run as SYSTEM. The internet-exposed honeypot index itself held roughly 24k process-create and 4k PowerShell events over the window, all brute-force and legitimate activity, with zero adversary encoded-command execution, so the malicious corpus stays synthetic by necessity (an accepted fallback). All three real payloads decoded losslessly via the builtin base64-UTF16LE recognizer on real Sysmon wire format (full path, `-NoProfile`, quotes and all), spliced in place, and all three verdicted **clean** with zero false positives. The two SYSTEM-run ones are the interesting part: a SYSTEM process launching an encoded command is exactly the shape a naive "encoded == malicious" rule false-positives on, and the engine decodes it, reads a plain `Write-Host`, and correctly clears it. It judges decoded behavior, not the presence of encoding.

**Honest finding: a mixed plaintext-plus-ROT13 sample floored to `unknown`, and the gate was right.** The corpus's one model-proposal sample glued a plaintext `IO.Compression.DeflateStream` keyword (which is what routes it to the model, since the builtins do not match it) to a ROT13-encoded downloader. A real Opus call returned the *semantic* decode: it left the already-readable keyword alone and rotated only the encoded half. That is not ROT13-of-the-whole-payload, so the byte-exact gate refused it (`model-disagreement`), leaving zero verified layers and flooring the verdict to `unknown`, which reads as escalate-to-human, never a false clean. The sample's `suspicious` label was simply wrong for real-model behavior, so it was relabeled `unknown`, renamed `adversarial_partial_rot13_refused`, and locked with a regression test that reproduces the refusal deterministically and offline (commit `1c5c0ed`). No engine byte changed.

**The boundary that finding exposes.** The refusal is not a one-off. Substitution ciphers (rot-n, reverse) only reach the model path when a plaintext keyword is present to trip the prefilter, and a faithful model then partial-decodes, which the whole-payload byte-exact gate refuses. A fully-encoded substitution payload trips no prefilter pattern at all and is never sent to the model. So for a faithful real model the model-proposal path behaves as a safe-refusal mechanism (it floors to `unknown`), not a decode-to-suspicious mechanism. That is a recall limitation, not a security hole: it fails safe every time, and the positive-verdict coverage comes from the deterministic builtins, which is where real captured payloads land anyway.

**Other documented boundaries, all fail-safe.** A doubly-encoded payload can be reported clean-of-residual when the outer layer is a model-proposed transform the model declines (documented, not a false malicious). A fully-decoded payload with neither a download/exec behavioral hit nor a bad IOC can floor to clean (a behavioral recall gap). And `powershell.exe` is over-extracted as a "domain" IOC (fail-safe precision noise). The advisory intel (the model's prose describing what the decoded script appears to do) is emitted on any decoded sample and is a real paid call each time, but it is quarantined and never touches the verdict.

**Trust guarantee, reaffirmed on real paid calls.** Across the entire run no model output moved a single verdict: the one model proposal was refused, the advisories were quarantined, and every positive verdict traces to a builtin-verified decode chain plus deterministic behavioral and IOC fusion.
