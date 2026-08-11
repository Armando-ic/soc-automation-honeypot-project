# Security Incident Report — INC-2026-002

| Field | Value |
|---|---|
| Report ID | INC-2026-002 |
| Report date/time (UTC) | 2026-08-11 |
| Analyst | Honeypot operator (project owner) |
| Status | **Monitoring** — asset deliberately kept live, session resident, no containment action taken |
| Classification | TLP:AMBER (internal) |
| Related | [INC-2026-001](INC-2026-001-first-interactive-intrusion.md) · [Tier-1 concealment experiment](../session-logs/TIER1-CONCEALMENT.md) |

---

## 1. Executive summary (BLUF)

**At 08:55:10 UTC on 2026-08-11, a second unidentified external actor established an interactive RDP
desktop session on our internet-exposed Windows honeypot using the same burned local administrator
credential.** They stayed **38.9 seconds**, opened Task Manager twice, and disconnected without running
anything else — creating no accounts, installing no persistence, making no outbound connection.

Two things make this more interesting than a repeat of [INC-2026-001](INC-2026-001-first-interactive-intrusion.md):

1. **The credential was handed off, not re-cracked.** `45.142.193.145` — the actor that originally cracked
   this password on 2026-08-06 — re-validated it at 08:51:27, and **3 minutes 34 seconds later a completely
   different address opened the interactive session.** The address that logged in has **zero** failed
   password attempts against this host across 30 days. It arrived already holding the credential.
2. **This was the first landing since the host's instrumentation was disguised**, and the operator stayed
   *less* time than the one who saw the instrumentation plainly. That is a null result for the concealment
   hypothesis and is recorded as such.

**There is no confirmed impact.** The affected asset is a purpose-built decoy holding no production data in
an un-peered VNet. **No action is required from the reader.**

## 2. Severity & confidence

| | |
|---|---|
| **Severity** | **Medium** |
| **Confidence** | **High** for the compromise, timings and impact assessment. **Moderate** for the credential-handoff interpretation, which is inference from timing and the absence of guessing, not from evidence of a transaction. |
| **Rationale** | Unchanged from INC-2026-001 and repeated here so this report stands alone. In production, confirmed interactive administrator access by an unknown external party is **Critical** without argument. Calibrated to *this* environment it is **Medium**: the asset is a decoy built to be compromised, holds no production data, sits in an un-peered VNet with no lateral path to real infrastructure, and its egress is restricted by a static NSG to Splunk:9997 / DNS:53 / web, with an automated egress-deny brake behind that. The compromise is genuine and fully confirmed — hence High confidence, not Low severity — but the blast radius was bounded by design and nothing was done. |

## 3. What happened

The host had been running with two weak local administrator accounts as bait since 2026-08-06, with account
lockout disabled so every guess is genuinely evaluated. The credential is known to be circulating: four
distinct external actors authenticated with it inside 30 hours during INC-2026-001.

On **2026-08-10** the host's instrumentation was deliberately disguised as a controlled experiment (Sysmon's
service, driver and binary renamed; the Windows computer name changed to a neutral, production-shaped
value). Exactly one variable was changed, and the data plane was verified intact end to end before the watch
resumed. Full design and result: [`TIER1-CONCEALMENT.md`](../session-logs/TIER1-CONCEALMENT.md).

**The next landing came roughly 15 hours later.** At 08:51:27 `45.142.193.145` performed a Type 3 network
validation of the credential. That address is the one that first cracked this password on 2026-08-06 and is
the earliest external address ever observed touching this host (2026-07-27). Three and a half minutes later,
`185.180.222.178` — an address never seen before — performed two Type 3 validations six seconds apart and
then opened a **Logon Type 10 (RemoteInteractive)** desktop session.

The desktop shell loaded in 3.7 seconds. Server Manager auto-launched from its scheduled task and raised a
UAC consent prompt. Twenty-four seconds after logon the actor opened **Task Manager, twice**, and fourteen
seconds after that they disconnected.

**The only human-initiated processes in the entire window were those two Task Manager launches**, both
parented by `explorer.exe`, meaning a person clicked them. Everything else running under the compromised
account was standard interactive-logon scaffolding parented by `svchost`, `services`, `winlogon` or
`userinit` — including Server Manager and the systray components, which are auto-start items and must not be
miscounted as actor behaviour.

**Assessment: this was access triage, by a second operator, following the same playbook as the first.**

## 4. Timeline (UTC)

| Time (UTC) | Event |
|---|---|
| 2026-08-10 15:28:19.862 | `216.225.207.214` — Type 3 validation. Known INC-2026-001 actor on a ~70h cadence |
| 2026-08-10 ~17:58 | **Instrumentation disguised** (operator action, Tier-1 concealment). Data plane re-verified green |
| **2026-08-11 08:51:27.508** | **`45.142.193.145` — Type 3 validation.** The original cracker of this credential re-confirms it is live |
| 2026-08-11 08:55:01.740 | `185.180.222.178` — Type 3 validation (first sighting of this address, ever) |
| 2026-08-11 08:55:04.813 | `185.180.222.178` — Type 3 validation (second), **+3.073s** |
| **2026-08-11 08:55:10.834** | **Logon Type 10 — RemoteInteractive session established, +6.021s.** `Logon_Process=User32`. `4648` (explicit credentials) fires in the same instant. Tripwire fired to Discord within seconds |
| 2026-08-11 08:55:11.644 | `rdpclip.exe` starts — the client had **clipboard redirection enabled** |
| 2026-08-11 08:55:12.603 → .635 | **14 × `4697`** per-user service instances, a 32 ms burst (session LUID suffix `_39289f2b`). This is the host's noise floor, not persistence |
| 2026-08-11 08:55:14.506 | `explorer.exe` — desktop shell loaded, **+3.672s** |
| 2026-08-11 08:55:18.428 / :19.136 | `ServerManager.exe` ×2 (auto-launch from scheduled task) with a `consent.exe` UAC prompt at :18.477 |
| **2026-08-11 08:55:35.104** | **`Taskmgr.exe /4`**, parent `explorer.exe`, **+24.270s** |
| **2026-08-11 08:55:36.604** | **`Taskmgr.exe /4`** again, parent `explorer.exe` |
| 2026-08-11 08:55:49.709 | **Event `4779` — session DISCONNECTED** (`RDP-Tcp#0`). Not a logoff |
| 2026-08-11 08:55:51.119 | `LogonUI.exe` — console returns to the logon screen |
| | **Total interactive dwell time: 38.875 seconds** |

## 5. Dwell-time comparison against INC-2026-001

The host was otherwise unchanged between the two intrusions except for the concealment.

| Phase | INC-2026-001 (instrumentation visible) | INC-2026-002 (instrumentation disguised) |
|---|---|---|
| Logon → shell (`explorer.exe`) | 3.95s | 3.67s |
| Logon → first Task Manager | 15.07s | **24.27s** |
| **First Task Manager → disconnect** | **39.04s** | **14.61s** |
| **Total dwell** | **54.11s** | **38.88s** |
| Entry sequence | 2× Type 3, then Type 10 (+7s) | 2× Type 3, then Type 10 (+6.02s) |
| Clipboard redirection | Enabled | Enabled |
| Task Manager launches | 2, both `explorer.exe`-parented | 2, both `explorer.exe`-parented |
| Ended by | `4779` disconnect, no logoff | `4779` disconnect, no logoff |

**The disguised host got the shorter visit**, and the sharpest measure — time from opening Task Manager to
leaving, which controls for shell-load time — was **2.7× faster**. See §11 for what this does and does not
support.

## 6. Affected assets

| Asset | Type | Role / exposure |
|---|---|---|
| `vm-honeypot-win` | Azure VM, Windows Server 2022 | Purpose-built decoy. RDP/3389, SMB/445 and web exposed to the internet. Un-peered VNet (`10.66.0.0/24`) with no route to production. Egress restricted by static NSG to Splunk:9997, DNS:53 and web, with an automated egress-deny brake behind it. No production data. The in-guest Windows computer name was changed on 2026-08-10; the Azure resource name is unchanged. |

## 7. Indicators of compromise (IOCs)

| Indicator | Type | Verdict | Notes |
|---|---|---|---|
| `185.180.222.178` | IPv4 | **Confirmed interactive compromise** | First sighting ever. **Zero `4625` failed logons across 30 days** — never guessed a password against this host. Two Type 3 validations then the Type 10 session. Clipboard redirection enabled client-side |
| `45.142.193.145` | IPv4 | Confirmed compromise (validation only) | **Re-validated the credential 3m34s before the landing.** Originally cracked this password 2026-08-06 in ~60 guesses; the earliest external address ever seen on this host (2026-07-27). Persistent across three weeks |
| `216.225.207.214` | IPv4 | Confirmed compromise (validation only) | Type 3 at 2026-08-10 15:28. Known INC-2026-001 actor, ~70h re-validation cadence. Highest-volume sprayer observed (2,495 guesses in 24h) and never got in on its own |
| `113.203.61.61` | IPv4 | Prior confirmed compromise | INC-2026-001's interactive actor. Its **only** failed logon in 30 days came at 2026-08-08 02:22:22, **18 minutes after** its session ended — not an attempt to get in |
| `Taskmgr.exe /4` | Process | Benign binary, adversary use | Living-off-the-land discovery. Notable only because `explorer.exe` parentage proves human interaction. **Confirmed as the triage tool of choice across both operators** |

## 8. MITRE ATT&CK mapping

| Technique ID | Name | Tactic |
|---|---|---|
| **T1650** | **Acquire Access** | **Resource Development** |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access / Defense Evasion |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1082 | System Information Discovery | Discovery |
| T1057 | Process Discovery | Discovery |

**T1650 is new to this report and is the reason it exists.** The address that used the access never
performed the credential access — that was done by a different address five days earlier, which
re-validated the credential minutes before the handoff. This is the access-broker pattern observed directly
rather than inferred.

## 9. Impact assessment

**Confirmed impact: none.** Every post-exploitation check returned negative.

- **No account manipulation** — `4720 / 4722 / 4726 / 4728 / 4732` returned **0 events** across 24 hours
- **No persistence** — `4697` returned **exactly 14**, the host's documented noise floor, all in a 32 ms
  burst, every `Service_File_Name` under `System32` and every Subject `S-1-5-18`. The single `4698` in the
  window is a **Windows Defender scheduled scan task**, created by `LOCAL SYSTEM` under the machine account
  on 2026-08-10 during operator maintenance, binary `MpCmdRun.exe` under `C:\ProgramData\Microsoft\Windows
  Defender\Platform\` — unrelated to this intrusion and characterised rather than waved away
- **No outbound network activity.** All 8 Sysmon `EventCode=3` events in the session window are inbound RDP
  to `10.66.0.4:3389` by `svchost.exe` as `NT AUTHORITY\NETWORK SERVICE` — the TermService listener
  accepting the connection. Independently corroborated by the brake reporting `max_distinct_dst: 1`
- **No process activity beyond scaffolding** — 27 processes ran as the compromised account across the 24h
  window; only two were `explorer.exe`-parented, and both were Task Manager
- **The automated egress brake never fired**, correctly: there was no fan-out to trip it. The NSG was
  verified afterwards still holding its clean 5-rule outbound baseline with no deny residue

**Potential impact, had the actor chosen to act:** bounded by design, unchanged from INC-2026-001. The
un-peered VNet gives no path to production; the static NSG blocks reverse shells on arbitrary ports, mining
pools and outbound scanning before any control needs to react. Concentrated single-destination abuse over
web ports remains the known residual gap, accepted in writing under the programme's Sign-off 2.

**Residual exposure at time of writing:**
1. The session was **disconnected, not logged off** — it remains resident on the host and is reconnectable.
2. The credential is now demonstrably circulating among **at least five distinct actors** and is being
   actively re-validated and handed between them. It is fully burned and must never be reused anywhere.

## 10. Response actions taken

| Action | By | When (UTC) | Result |
|---|---|---|---|
| Weak-credential tripwire fired to Discord | Automated (Splunk saved search → n8n → Discord) | 2026-08-11 08:55:1x | Correct severity, correct account, correct source IP, delivered in seconds |
| Egress fan-out brake | Automated | n/a | Did not fire — correctly, no fan-out occurred |
| Post-exploitation hunt (accounts, persistence, processes, network, files, DNS) | Analyst | 2026-08-11 | All negative |
| Brake + NSG state verified after the fact | Analyst | 2026-08-11 15:38 | Feeder healthy (`stale:false`, posting on the minute); NSG clean 5-rule baseline, no deny residue |
| Containment | — | — | **Deliberately none.** Capture posture; harm is bounded by the static NSG envelope plus the automated brake |
| Teardown decision | Operator | 2026-08-11 | **Decided: do NOT snapshot and tear down. The host stays live.** The B9 question is now closed |

## 11. Analyst assessment

### The credential is a traded asset, and we watched it change hands

Across both incidents, **neither address that used interactive access ever guessed a password on this host.**
`185.180.222.178` has zero failed logons in 30 days. `113.203.61.61` has exactly one, and it came 18 minutes
*after* it had already been inside. The ~15,000 guesses this host absorbed came from entirely different
infrastructure.

Combined with the original cracker re-validating the credential **3 minutes 34 seconds before a different
address used it**, the most economical explanation is a division of labour: one party finds and maintains
credentials, another party uses them. Whether that boundary is a sale, a shared pool or one group with
separate spray and access infrastructure is not something this data can distinguish, and the report does not
claim to. **Confidence: moderate**, and it rests on timing plus the absence of guessing.

### Two operators, one playbook

The entry sequences are near-identical: two Type 3 validations a few seconds apart, then a Type 10 six to
seven seconds later, clipboard redirection enabled, shell in under four seconds, Task Manager twice via the
shell, then disconnect without logging off. **Two independent actors three days apart converging on the same
40-second routine is a stronger finding than either session alone** — it indicates a standardised
access-triage procedure and probably shared tooling, not one operator's habit.

### The concealment experiment returned a null

INC-2026-002 is the first landing since the host's instrumentation was disguised, and **dwell went down, not
up** (38.9s vs 54.1s). The hypothesis that INC-2026-001's operator left because they saw `Sysmon64.exe` in
Task Manager is **not supported**.

**This must not be over-read in either direction.** It is n=1 against n=1, two different actors on different
days; a 15-second difference is well inside the variation you would expect between two people. The defensible
claim is the *absence of any lengthening*, not that concealment made things worse.

What the session does suggest is a better candidate for the real tell. **Server Manager auto-launches on this
host and presents a server with no roles and nothing configured**, and it did so before Task Manager was ever
opened — which also explains why this operator took nine seconds longer to reach Task Manager. An empty
Server Manager is a louder statement that a box is worthless than a process list ever was.

### The ask

**No action required.** Reported for the record. The credential remains burned, the host remains
deliberately live by operator decision, and the next lever under consideration is furnishing the host with
plausible content rather than further concealment.

---

## Appendix — evidence

Splunk index `honeypot`; dashboard **"Honeypot - Attacker Session (B8)"**, Incident Window
`2026-08-11 08:55 → 08:57`.

```spl
# LANDING DETECTION. Filter NOTHING and read Logon_Type.
# Logon_ID is a MULTIVALUE field carrying the Subject ID *and* the New Logon ID, so a
# Type 3 row reads {0x0, <real id>}. `| where Logon_ID!="0x0"` therefore deletes the
# whole row and silently hides every Type 3 landing. That filter belongs ONLY in a
# session-correlation query that does `stats ... BY Logon_ID`.
index=honeypot source="WinEventLog:Security" EventCode=4624 user IN ("backup","Administrator") earliest=-24h
| eval src_ip=coalesce(src_ip, Source_Network_Address)
| table _time, src_ip, user, Logon_Type, Logon_ID, Logon_Process | sort - _time

# DISCONNECT vs LOGOFF. 4779 is a DISCONNECT: the session stays resident and
# reconnectable, and a logon/logoff correlation reports it OPEN indefinitely.
index=honeypot source="WinEventLog:Security" (EventCode=4778 OR EventCode=4779 OR EventCode=4634 OR EventCode=4647) earliest=-24h
| table _time, EventCode, user, Logon_ID, src_ip, Session_Name | sort _time

# DID THE ACCESS ADDRESS EVER GUESS A PASSWORD? Raw-text search so the answer does not
# depend on any field extraction. Returned exactly one 4625 across 30 days, belonging to
# the INC-2026-001 actor and dated AFTER its session.
index=honeypot "185.180.222.178" OR "113.203.61.61" earliest=-30d
| stats count, min(_time) AS first, max(_time) AS last BY EventCode
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T") | sort EventCode

# WHO RAN ANYTHING. Do NOT blanket-filter NT AUTHORITY\SYSTEM — privilege escalation and
# service installs run AS SYSTEM. Split by user first, then pivot on explorer parentage,
# because shell parentage means a person clicked.
index=honeypot sourcetype=XmlWinEventLog EventCode=1 earliest=-24h | stats count BY user
index=honeypot sourcetype=XmlWinEventLog EventCode=1 earliest=-24h ParentImage="*explorer.exe"
| table _time, User, Image, CommandLine, ParentImage | sort _time

# PERSISTENCE. Include 4697 — omitting it is how INC-2026-001's first pass reported a
# clean result on incomplete evidence.
index=honeypot source="WinEventLog:Security" (EventCode=4720 OR EventCode=4722 OR EventCode=4726 OR EventCode=4728 OR EventCode=4732 OR EventCode=4697 OR EventCode=4698) earliest=-24h
| table _time, EventCode, Service_Name, Service_File_Name, Target_Account_Name | sort _time

# NETWORK / FILE / DNS. Run the control FIRST to prove the events exist, then window it.
# Do NOT filter these on `user` — see the trap note below.
index=honeypot sourcetype=XmlWinEventLog (EventCode=3 OR EventCode=11 OR EventCode=22) earliest=-24h
| stats count BY EventCode
index=honeypot sourcetype=XmlWinEventLog (EventCode=3 OR EventCode=11 OR EventCode=22) earliest="08/11/2026:08:55:00" latest="08/11/2026:08:57:00"
| table _time, EventCode, User, Image, DestinationIp, DestinationPort, TargetFilename, QueryName | sort _time
```

### ⚠️ Query traps this incident added

- **Do not filter Sysmon event codes on `user`.** There are two distinct fields: lowercase `user`
  (normalised, bare account name) and capital `User` (raw Sysmon, `HOST\account`). The lowercase alias is
  populated on `EventCode=1` but **not** on `3 / 11 / 22`, so `user="*Administrator"` on those codes matches
  nothing and returns a confident **0 events**. It cost a full round trip here. Run an unfiltered
  `| stats count BY EventCode` control first, then window by time and display `User` as a column instead of
  filtering on it.
- **The linked-token pair is not always `0x20` apart.** INC-2026-001 recorded the standard/elevated pair as
  differing by exactly `0x20`. This session's pair is `0x39283A55` and `0x39283A36` — **`0x1F` apart**. The
  reliable test is *two adjacent Logon_IDs at an identical timestamp with identical source, account, type and
  process*, not a fixed delta. One session, two IDs, do not double count.
- **`4648` fires once per intrusion**, at the same instant as the Type 10, in both incidents — the RDP client
  supplying explicit credentials. It was not previously being collected in the landing query and is a useful
  confirmatory signature.

### Evidentiary strength — stated plainly

Not every negative in §9 carries the same weight, and the report would be misleading if it implied otherwise.

| Finding | Strength | Why |
|---|---|---|
| Dwell times, entry sequence, process parentage | **Exact** | Millisecond timestamps from Sysmon and Security channels |
| No account manipulation, no persistence | **Strong** | Zero events across five account codes; `4697` exactly at a well-characterised baseline |
| No outbound network | **Strong** | Two independent sensors agree (Sysmon `EventCode=3`; brake `max_distinct_dst: 1`) |
| No file writes, no DNS | **Weak but consistent** | This host emits ~39 `EventCode=11` and ~72 `EventCode=22` per 24h, so the *expected* count in a 2-minute window is 0.05 and 0.10. Zero is what an idle box looks like and proves little. The Sysmon config also only watches selected paths for file creation |
| Brake behaved correctly | **Strong for this incident, limited in general** | The NSG showing no deny residue proves it did not fire here. `trips:0` from `/brake/feed-status` is **windowed, not lifetime** (`samples` caps at 2000) and cannot carry that claim. Across two real intrusions there has still been **zero fan-out to trip the brake, so it remains proven only against dry-runs** |
| Concealment had no effect on dwell | **Suggestive, not conclusive** | n=1 against n=1, two different actors |
| Credential was handed off | **Moderate** | Timing plus a 30-day absence of guessing. No evidence of a transaction itself |
