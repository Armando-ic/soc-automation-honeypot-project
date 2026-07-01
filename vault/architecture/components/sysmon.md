---
status: active
updated: 2026-04-30
sub_project: D1
related: [[../current-state]], [[splunk]], [[../../subprojects/2026-04-30-detection-foundations/runbook]], [[../../detections/README]]
---

# Sysmon

## What it is

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) is Sysinternals' Windows system service that logs detailed process / file / network / registry telemetry to a dedicated Windows Event Log channel. It supplements (does not replace) the native Security / Application / System logs. In a SOC, Sysmon is the de-facto endpoint-telemetry fabric for Windows hosts that don't have a full EDR.

## Where it runs

| | |
|---|---|
| Host | Azure VM `vm-soc-v2-win` (Windows Server, `10.0.0.4` private / `x.x.x.x` public, Central US). Historical: ran on local-VMware Win10 `DESKTOP-VNEF7PC` (192.168.129.130) before Phase 1 (2026-05-22). |
| Service name | `Sysmon64` |
| Channel | `Microsoft-Windows-Sysmon/Operational` |
| Forwarder | Existing Splunk Universal Forwarder (config edited only — see splunk.md) |
| Splunk index | `mydfir-project` |
| Splunk sourcetype | `XmlWinEventLog` (shared with Security/App/System; differentiate by `source=`, see below) |
| Splunk source filter | `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` |

## Configuration

| | |
|---|---|
| Config source | [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (`master` branch) |
| Config file | `sysmonconfig-export.xml` (off-the-shelf — **no edits**) |
| Config commit SHA | `1836897f12fbd6a0a473665ef6abc34a6b497e31` |
| Config commit msg | "Merge pull request #151 from Neo23x0/patch-8" |
| Config schema version | 4.50 (Sysmon 15.20 supports 4.91, but accepts older configs) |
| Config file SHA256 | `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162` (123,257 bytes) |
| Sysmon binary | `C:\Tools\Sysmon\Sysmon64.exe` |
| Sysmon binary version | `Sysinternals Sysmon 15.20` (FileVersion 15.20) |
| Hash algorithms | MD5, SHA256, IMPHASH (per the SwiftOnSecurity config's `<HashAlgorithms>` block — verified populated for `powershell.exe` 2026-04-30) |
| Install command | `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
| Install date | 2026-04-30 |
| Source download script | `scripts/d1_phase1_sysmon_install.py` (re-runnable) |

D1 mandate: no edits to the SwiftOnSecurity XML. Tuning is post-D1, driven by observed lab volume.

## Splunk add-on integration

Two Splunk add-ons participate in parsing Sysmon events:

| Add-on | App ID | Version | Role |
|---|---|---|---|
| **Splunk Add-on for Microsoft Windows** | `Splunk_TA_windows` | 10.0.1 | General Windows Event Log channel parsing; sets `sourcetype=XmlWinEventLog` for the Sysmon channel. |
| **Splunk Add-on for Microsoft Sysmon** | `Splunk_TA_microsoft_sysmon` | 5.0.0 | Sysmon-specific field extractions; props/transforms keyed on `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. |

The Sysmon-specific add-on is what gives us first-class field extraction (`Image`, `CommandLine`, `ParentImage`, `Hashes`, `User`, etc.) on the XML-formatted events. Without it, fields would still be in `_raw` but require manual extraction.

## EventCode reference

High-yield codes the SwiftOnSecurity config emits in this lab (the full Sysmon catalog is larger; this is the analyst's working set):

| EventCode | Name | When it fires |
|---|---|---|
| 1 | Process Create | A new process is launched. Highest-volume code; the headline event. |
| 3 | Network Connect | A process initiates a network connection. |
| 4 | Sysmon service state changed | Captured at install or service restart. |
| 5 | Process Terminate | A process exits. **Filtered aggressively by SwiftOnSecurity** — rarely seen in our lab. |
| 7 | Image Loaded | A DLL or driver is loaded into a process. (Filtered aggressively by SwiftOnSecurity.) |
| 8 | CreateRemoteThread | Thread injection into another process. |
| 10 | Process Access | A process opens a handle into another process. **The LSASS pivot** for credential dumping detection. |
| 11 | File Create | A file is written to disk. |
| 12 / 13 / 14 | Registry events | Registry key created (12) / value set (13) / key renamed (14). Our lab sees mostly 13 — 12 is filtered. |
| 16 | Sysmon config changed | Captured at install (`Sysmon64.exe -i`). |
| 17 / 18 | Pipe events | Named pipe created (17) / connected (18). Useful for lateral-movement detection. |
| 22 | DNS Query | A DNS lookup is performed. |
| 23 | File Delete | A file is deleted. **Filtered aggressively by SwiftOnSecurity** — rarely seen in our lab. |

### EventCode coverage in *our* lab (baseline 2026-04-30)

What the SwiftOnSecurity config actually emitted in the first ~15 minutes of operation, after seeded activity (process spawns + network connect + file write + registry set + DNS query):

| EventCode | Count |
|---|---|
| 1 (Process Create) | 108 |
| 11 (File Create) | 4 |
| 13 (Registry Value Set) | 4 |
| 3 (Network Connect) | 3 |
| 22 (DNS Query) | 2 |
| 16 (Sysmon Config Changed) | 1 |
| 4 (Sysmon Service State) | 1 |
| 8 (CreateRemoteThread) | 1 |

**Notable absences** (the SwiftOnSecurity config intentionally filters these): EventCode 5 (Process Terminate), 23 (File Delete), 12 (Registry Object Add). Any future detection that depends on these EventCodes will need a config tune, a different EventCode pivot, or accept the gap.

See [[../../subprojects/2026-04-30-detection-foundations/notes]] for the original capture context.

## Field reference

High-frequency Sysmon fields the SwiftOnSecurity config populates and the Splunk Add-ons extract:

| Field | Meaning |
|---|---|
| `_time` | Splunk-assigned event timestamp (parsed from Sysmon's UTC stamp). |
| `EventCode` | The Sysmon event type (1, 3, 7, ...). |
| `host` | The Windows hostname the event originated from. **Use this, not `ComputerName`** — the Splunk Add-on for Microsoft Sysmon populates `host`; `ComputerName` is empty/null when piped through `\| stats by`. |
| `User` | Account context the process ran under (e.g., `DESKTOP-VNEF7PC\mydfir`). |
| `Image` | Full path to the executable. |
| `CommandLine` | Command-line string the process was invoked with. |
| `ParentImage` | Full path to the parent process's executable. **High-signal column for triage** — see ParentImage cheat sheet below. |
| `ParentCommandLine` | Parent process's command line. |
| `ProcessId` / `ParentProcessId` | PIDs. |
| `Hashes` | MD5 / SHA1 / SHA256 / IMPHASH of the executable, per `<HashAlgorithms>` in the config. **Populated** for our lab (verified 2026-04-30). |
| `TargetFilename` | (EventCode 11/23) the file path being created or deleted. |
| `TargetObject` | (EventCode 12/13/14) the registry key or value path. |
| `Details` | (EventCode 13) the new value being set. |
| `QueryName` | (EventCode 22) the DNS name being looked up. |
| `QueryStatus` | (EventCode 22) the DNS resolver result code. |
| `DestinationIp` / `DestinationPort` | (EventCode 3) the network connection target. |
| `SourceImage` / `TargetImage` | (EventCode 10) the calling and called processes for handle access. |

### ParentImage triage cheat sheet

| ParentImage | Typical interpretation |
|---|---|
| `winword.exe` / `excel.exe` / `outlook.exe` | Phishing macro launched a child process |
| `cmd.exe` from interactive logon | Manual analyst use, usually benign |
| `wscript.exe` / `cscript.exe` | Scripted attack chain (`.vbs`/`.js` payload) |
| `WmiPrvSE.exe` | WMI-launched (could be lateral movement OR a synthetic test like Atomic Test Harness) |
| `services.exe` | Service control launched a child — e.g., scheduled-task expansion |
| Unknown / non-system parent | Very suspicious; investigate the parent's `Image` and origin |

## Why `source=` (not `sourcetype=`) is the channel filter

Splunk's Add-on for Microsoft Windows assigns the same sourcetype (`XmlWinEventLog`) to **every** Windows Event Log channel — Security, Application, System, and Sysmon's Operational channel all share it. The way to filter to Sysmon-only events is the `source=` field, not `sourcetype=`:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ...
```

The `XmlWinEventLog:` prefix (not the bare `WinEventLog:`) is the canonical convention when the Splunk Add-on for Microsoft Sysmon is installed — that add-on's props/transforms are keyed on this exact source value. If a future Splunk install lacks the Sysmon-specific add-on, the source value defaults to `WinEventLog:Microsoft-Windows-Sysmon/Operational` and field extraction is generic.

The `:` and `/` in the channel name break unquoted SPL parsing. **Quotes are required.**

All future SPL against Sysmon should follow the `source="XmlWinEventLog:..."` pattern.

## How to verify Sysmon is working

Two queries cover the common diagnostic questions:

**"Is Sysmon emitting at all?"**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-1h
| stats count by EventCode | sort -count
```

Expected: a non-trivial distribution (matches the EventCode coverage table above; differences are baseline-activity-driven). If empty, the forwarder isn't picking up the channel — see the [[../../subprojects/2026-04-30-detection-foundations/runbook]]'s Recoveries section.

**"End-to-end smoke test"**

```powershell
# On the Windows VM
Start-Process notepad.exe; Start-Sleep 2; Stop-Process -Name notepad
```

Then in Splunk:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\notepad.exe" earliest=-5m
| table _time, host, User, Image, CommandLine, ParentImage
```

Expected: at least one row within ~60 seconds (typical observed indexing lag in our lab is ~5-30 seconds).

## References

- [Sysinternals Sysmon docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — official.
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — the config we run.
- [Splunk Add-on for Microsoft Sysmon on Splunkbase](https://splunkbase.splunk.com/app/5709) — the field-extraction add-on.
- [MITRE Cyber Analytic Repository](https://car.mitre.org/) — community resource for technique-to-EventCode mapping.
- [[splunk]] — Splunk component page; the consumer of Sysmon events.
- [[../../subprojects/2026-04-30-detection-foundations/runbook]] — operational runbook for the detection lab.
- [[../../detections/README]] — the per-MITRE-technique detection catalog Sysmon feeds.
