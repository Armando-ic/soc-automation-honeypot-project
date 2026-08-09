# Security Incident Report — INC-2026-001

| Field | Value |
|---|---|
| Report ID | INC-2026-001 |
| Report date/time (UTC) | 2026-08-08 |
| Analyst | Honeypot operator (project owner) |
| Status | **Monitoring** — asset still live, session resident, no containment action taken (deliberate) |
| Classification | TLP:AMBER (internal) |

---

## 1. Executive summary (BLUF)

**At 02:03:32 UTC on 2026-08-08, an unidentified external actor established an interactive RDP desktop
session on our internet-exposed Windows honeypot using a deliberately weak local administrator
credential.** They stayed **54 seconds**, opened Task Manager twice, and disconnected without running
anything else, creating no accounts, installing no persistence, and generating no outbound traffic.

This was the **fourth distinct external actor** to authenticate with that credential in roughly 30 hours.
The other three were automated validations lasting under one second each.

**There is no confirmed impact.** The affected asset is a purpose-built decoy holding no production data,
sitting in an un-peered VNet with egress restricted to three destinations. **No action is required from
the reader** — this report exists to document the first genuine hands-on-keyboard compromise of the
honeypot programme and the behavioural intelligence it produced.

## 2. Severity & confidence

| | |
|---|---|
| **Severity** | **Medium** |
| **Confidence** | **High** |
| **Rationale** | There is real tension in this rating and it is worth stating plainly. In a production environment, confirmed interactive administrator access by an unknown external party would be **Critical** without argument. Calibrated to *this* environment it is **Medium**: the asset is a decoy built to be compromised, it holds no production data, its VNet is un-peered so there is no lateral path into real infrastructure, outbound traffic is restricted by a static NSG to Splunk:9997 / DNS / web:443, and an automated egress brake stands ready behind that. The compromise is genuine and fully confirmed — hence High confidence and not Low severity — but the blast radius was bounded by design and nothing was actually done. |

## 3. What happened

An internet-facing Windows Server 2022 host with RDP (3389) exposed to the internet was deliberately
seeded with two weak local administrator accounts as bait, with account lockout disabled so that every
password guess would genuinely be evaluated. Over the preceding week the host absorbed thousands of
credential-guessing attempts per day from a wide, largely automated population.

Once a genuinely weak, top-of-list password was set on the bait account (2026-08-06 ~17:04 UTC), the
first successful authentication followed in **3 hours 48 minutes**. Over the next 30 hours four distinct
external addresses authenticated successfully. Three of them behaved identically: a **Logon Type 3**
network authentication lasting **0.0 seconds**, with no session established and nothing executed. That
pattern is consistent with automated credential validation — a brute-force operation confirming a hit and
recording it, rather than using it. One of those addresses returned on an almost exactly **15-hour**
interval, suggesting a scheduled re-validation job keeping the credential inventory fresh.

The fourth actor was different. After two Type 3 validations nine seconds apart, they escalated to a
**Logon Type 10 (RemoteInteractive)** session — a real remote desktop. The desktop shell loaded, they
opened **Task Manager twice**, and 54 seconds after connecting they disconnected the session.

The only human-initiated processes in the entire window were those two Task Manager launches, both
parented by `explorer.exe`, meaning a person clicked them rather than a script spawning them. Every other
process running under the compromised account was standard Windows interactive-logon scaffolding
(`userinit`, `explorer`, `rdpclip`, `sihost`, `ctfmon`, `TSTheme`, Server Manager and systray components),
all parented by `svchost`, `services`, `winlogon` or `userinit`.

**Assessment: this was access triage.** The actor connected to evaluate what the machine was, used Task
Manager to inspect its specifications and running processes, concluded it was not worth deploying tooling
on, and left.

## 4. Timeline (UTC)

| Time (UTC) | Event |
|---|---|
| 2026-08-06 ~17:04 | Bait credential set to a genuinely weak value and validated as working (operator action) |
| 2026-08-06 20:52:31 | **First successful compromise** — `45.142.193.145`, Type 3, 0.0s. 3h48m after the credential went live |
| 2026-08-07 11:51:46 | `45.142.193.145` re-validates — Type 3, 0.0s. **14h59m** after its first access |
| 2026-08-07 16:49:45 | `216.225.207.214` — Type 3, 0.0s (second distinct actor) |
| 2026-08-07 20:01:40 | `38.123.149.14` — Type 3, 0.0s (third distinct actor) |
| 2026-08-08 02:03:23 | `113.203.61.61` — Type 3 validation (fourth distinct actor) |
| 2026-08-08 02:03:25 | `113.203.61.61` — Type 3 validation (second) |
| **2026-08-08 02:03:32** | **Logon Type 10 — RemoteInteractive RDP session established.** Detection fired to Discord |
| 2026-08-08 02:03:33 | `rdpclip.exe` starts — the client had **clipboard redirection enabled** |
| 2026-08-08 02:03:36.463 | `explorer.exe` — desktop shell finishes loading |
| **2026-08-08 02:03:47.578** | **`Taskmgr.exe /4`** launched, parent `explorer.exe` |
| **2026-08-08 02:03:50.576** | **`Taskmgr.exe /4`** launched again, parent `explorer.exe` |
| 2026-08-08 02:04:26.622 | **Event 4779 — session DISCONNECTED** (`RDP-Tcp#1`). Not a logoff |
| | **Total interactive dwell time: ~54 seconds** |

**Detection latency:** the weak-credential tripwire fired to Discord within seconds of the initial Type 3
authentication, ahead of the interactive session being established.

## 5. Affected assets

| Asset | Type | Role / exposure |
|---|---|---|
| `vm-honeypot-win` | Azure VM, Windows Server 2022 | Purpose-built decoy. RDP/3389, SMB/445 and web exposed to the internet. Un-peered VNet (`10.66.0.0/24`) with no route to production infrastructure. Egress restricted by static NSG to Splunk:9997, DNS:53 and web:80/443, with an automated egress-deny brake behind it. No production data. |

## 6. Indicators of compromise (IOCs)

| Indicator | Type | Verdict | Notes |
|---|---|---|---|
| `113.203.61.61` | IPv4 | **Confirmed interactive compromise** | Two Type 3 validations then the Type 10 session. The only actor to establish a desktop. Clipboard redirection enabled client-side |
| `45.142.193.145` | IPv4 | Confirmed compromise (validation only) | Two accesses, ~15h apart. **Also the first external address ever seen touching this host (2026-07-27)** — persistent for three weeks. Roughly 60 guesses before success |
| `216.225.207.214` | IPv4 | Confirmed compromise (validation only) | Highest-volume sprayer observed: **2,495** password guesses in 24h |
| `38.123.149.14` | IPv4 | Confirmed compromise (validation only) | Single Type 3 validation |
| `Taskmgr.exe /4` | Process | Benign binary, adversary use | Living-off-the-land discovery. Notable only because `explorer.exe` parentage proves human interaction |

## 7. MITRE ATT&CK mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access / Defense Evasion |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1082 | System Information Discovery | Discovery |
| T1057 | Process Discovery | Discovery |

## 8. Impact assessment

**Confirmed impact: none.** Every post-exploitation check returned zero.

- **No account manipulation** — `4720 / 4722 / 4726 / 4728 / 4732` returned 0 events
- **No persistence** — no scheduled tasks (`4698`), no service installs (`4697`)
- **No file writes** attributable to the actor
- **No outbound C2 or tool retrieval** — `/brake/feed-status` reported `max_distinct_dst: 0` across the window
- **No data accessed** — the host holds none
- **The automated egress brake never fired**, correctly: there was no fan-out to trip it

**Potential impact, had the actor chosen to act:** bounded by design. The un-peered VNet gives no path to
production. The static NSG permits outbound only to Splunk:9997, DNS and web:80/443, so reverse shells on
arbitrary ports, mining pools and outbound scanning were all blocked before any control needed to react.
Concentrated single-destination abuse over 80/443 remains the known residual gap, accepted in writing
under the programme's Sign-off 2.

**Residual exposure at time of writing:**
1. The session was **disconnected, not logged off** — it remains resident on the host and is reconnectable.
2. The credential is demonstrably circulating among **at least four distinct actors** and should be
   treated as fully burned.

## 9. Response actions taken

| Action | By | When (UTC) | Result |
|---|---|---|---|
| Weak-credential tripwire fired to Discord | Automated (Splunk saved search → n8n → Discord) | 2026-08-08 02:03:2x | Correct severity, correct account named, delivered in seconds |
| Backstop logon alert fired | Automated | 2026-08-08 02:03:2x | Fired as designed alongside the primary |
| Egress fan-out brake | Automated | n/a | Did not fire — correctly, no fan-out occurred |
| Post-exploitation hunt (accounts, persistence, processes, egress) | Analyst | 2026-08-08 | All negative |
| Containment | — | — | **Deliberately none.** Capture posture: the operation exists to observe, and harm is bounded by the static NSG envelope plus the automated brake |

## 10. Recommendations / next steps

| Priority | Recommendation | Owner |
|---|---|---|
| High | Treat the credential as fully burned. Do not reuse this value anywhere, in any environment | Operator |
| High | Decide the programme's next step: forensic snapshot and teardown, or increase the host's apparent value and run a further capture window | Operator |
| Medium | Take the B9 Step 0 forensic snapshot before any teardown. Note its value is unusually low here — nothing was written to disk — but it is procedurally correct and cheap | Operator |
| Medium | Record `Logon Type 10` as the standing bot-versus-human discriminator, alongside the existing link-local source test | Operator |
| Medium | Terminate the resident disconnected session if the host is to remain live | Operator |
| Low | Re-examine whether the egress brake should also bound concentrated single-destination traffic, given Sign-off 2's known gap | Operator |

## 11. Analyst assessment & the ask

The behaviour across all four actors is **consistent with a credential-access market rather than a
directed intrusion**: automated infrastructure sprays at scale, confirms hits, re-validates them on a
schedule, and a human eventually triages the access to decide whether it is worth using. Our host was
triaged and rejected in under a minute — a plain, direct demonstration that an empty server carries little
value to an operator, and the most useful finding of the engagement. **Confidence: high** for the
behavioural read; **moderate** for the market attribution, which is inference from behaviour rather than
from any evidence of a transaction.

**The ask: no action required.** This is reported for the record and to inform the decision on whether to
continue the capture. That decision is the operator's and is deliberately left open here.

---

## Appendix — evidence

Splunk index `honeypot`; dashboard **"Honeypot - Attacker Session (B8)"**, Incident Window
`2026-08-08 02:00 → 02:10`.

```spl
# Session correlation with duration. Logon_ID!="0x0" excludes the Subject logon ID
# artifact; 0x3E7 (LOCAL SYSTEM) is likewise not a session. A single RDP logon emits
# TWO adjacent real Logon_IDs differing by 0x20 (the standard/elevated linked-token
# pair) - one session, two IDs, do not double count.
index=honeypot source="WinEventLog:Security" (EventCode=4624 OR EventCode=4634 OR EventCode=4647) user IN ("backup","Administrator") earliest=-7d
| eval src_ip=coalesce(src_ip, Source_Network_Address)
| where Logon_ID!="0x0"
| stats min(_time) AS logon, max(eval(if(EventCode!=4624,_time,null()))) AS logoff, values(Logon_Type) AS types, values(src_ip) AS srcs BY Logon_ID
| eval dur=if(isnull(logoff),"OPEN",tostring(round(logoff-logon,1))."s")
| eval logon=strftime(logon,"%F %T") | sort - logon

# Disconnect vs logoff. 4779 is a DISCONNECT: the session stays resident and
# reconnectable, and a logon/logoff correlation will report it as OPEN indefinitely.
index=honeypot source="WinEventLog:Security" (EventCode=4778 OR EventCode=4779 OR EventCode=4634 OR EventCode=4647) earliest="08/08/2026:02:00:00"
| table _time, EventCode, user, Logon_ID, src_ip, Session_Name | sort _time

# Who ran anything at all. Do NOT blanket-filter NT AUTHORITY\SYSTEM when hunting:
# privilege escalation and service installs run AS SYSTEM. Split by User first.
index=honeypot sourcetype=XmlWinEventLog EventCode=1 earliest="08/08/2026:02:03:00" latest=now
| stats count BY User

# The human actions: explorer.exe parentage means a person clicked, not a script.
index=honeypot sourcetype=XmlWinEventLog EventCode=1 earliest="08/08/2026:02:03:00" latest=now ParentImage="*explorer.exe"
| table _time, User, Image, CommandLine, ParentImage | sort _time

# Persistence check - returned 0 events.
index=honeypot source="WinEventLog:Security" (EventCode=4720 OR EventCode=4722 OR EventCode=4726 OR EventCode=4728 OR EventCode=4732 OR EventCode=4697 OR EventCode=4698) earliest="08/08/2026:02:00:00"
```

**Scale context for the same period:** 5,599 wrong-password attempts against the bait account in 24 hours
(~233/hour), plus 566 attempts against usernames that do not exist. Account lockout was disabled
throughout, so every guess was genuinely evaluated rather than refused.

**Tradecraft note.** `216.225.207.214` made **2,495** guesses over 24 hours and never got in.
`45.142.193.145` made roughly **60** and was inside within four hours. Wordlist quality beat brute-force
volume by roughly six to one — raw spray throughput is a poor predictor of who compromises you first.
