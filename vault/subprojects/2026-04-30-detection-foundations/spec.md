---
status: draft
updated: 2026-04-30
sub_project: D1
approach: SwiftOnSecurity Sysmon (off-the-shelf) + ART manual run loop + one saved-search integration as worked example
related: [[README]], [[../2026-04-28-iris-escalation-gate/spec]], [[../../architecture/target-state]], [[../../architecture/components/splunk]]
---

# Spec — Sub-project D1: Detection Foundations

## Summary

D1 stands up a **detection-engineering observation lab** on top of the existing SOC pipeline. Sysmon is installed on the Windows 10 VM with SwiftOnSecurity's off-the-shelf config; the existing Splunk Universal Forwarder (already on that VM) carries the Sysmon channel into Splunk's `mydfir-project` index. Atomic Red Team is installed on the same VM so any MITRE technique can be invoked on demand. **One** technique — T1059.001 (PowerShell encoded command) — is taken end-to-end as a worked example: a hand-written SPL with `regex` flag-matching becomes a saved search that fires into the existing Splunk → n8n webhook, exercising the SOAR pipeline (A1's Claude triage + A2's gate). Because the Sysmon-shaped alert produces no network IOCs by default, the gate skips and Slack/Iris produce a plain alert, validating the gate-skipped branch on real production traffic.

A new `vault/detections/` directory with a per-technique template and a coverage-index README becomes the durable artifact for future technique runs. The runbook documents the exact "RDP / SSH to Windows VM → run ART → observe in Splunk" loop so future techniques are a routine, not a sub-project.

## Goal

D1 has three layered deliverables:

**Primary** — the foundation. Sysmon ingesting + ART installed + a documented loop (manual ART invocation + observation toolkit) for running any technique and observing it across Splunk's available log sources. This is what supports the user's stated learning goal: "I want to be able to run any MITRE technique and see how it looks in Splunk."

**Secondary** — the integration test. T1059.001 exercising the existing SOAR pipeline against a Sysmon-shaped alert, proving the pipeline accepts the new alert family without n8n changes. Outcome A (gate-skipped path) is expected; Outcome B (Claude decodes the base64 payload, finds an IOC, gate fires) is acceptable bonus variance — both validate the integration.

**Tertiary** — the catalog seed. A new `vault/detections/` directory populated with one worked-example page, a template, and an index, ready for "I ran T1003 today" entries to land cleanly. Inherited by sub-project C.

The **design driver** is job-prep — every D1 deliverable is something the user can point at in a SOC analyst interview and explain in 60–90 seconds: *Sysmon's role and config*, *EventCode 1's CommandLine pivot*, *SPL `regex` + `stats by`*, *the SOAR loop wiring*, *MITRE technique IDs and tactics*.

## Scope

### In scope

- **Install Sysmon** on the Windows 10 VM with SwiftOnSecurity's `sysmonconfig-export.xml` exactly as upstream publishes it. Document the upstream URL + commit SHA in the runbook.
- **Configure the existing Splunk Universal Forwarder** (already installed on the Windows VM) to capture the Sysmon channel (`Microsoft-Windows-Sysmon/Operational`) and forward to the existing `mydfir-project` index. This is an `inputs.conf` addition, not a new agent.
- **Verify ingestion** with a smoke test: a manually-spawned `notepad.exe` from a Windows cmd produces an EventCode=1 in Splunk within 60 seconds.
- **Install Atomic Red Team** on the Windows 10 VM via Red Canary's bootstrap script (`Install-AtomicRedTeam -getAtomics`).
- **Write the SPL detection** for T1059.001 (regex flag-match + parent-process surfacing + stats aggregation), annotated inline so the user can refer back when learning.
- **Create one Splunk saved search** wrapping the SPL, posting to the existing v2 production webhook URL on a 5-minute cron. Saved-search-name = `T1059.001 - PowerShell Encoded Command`.
- **Live-fire validation:** `Invoke-AtomicTest T1059.001 -TestNumbers <2 or per Phase 0>` triggers the saved search, fires the webhook, traces through the existing pipeline. Verify Slack post lands; Iris alert is created with `alert_iocs: []`; gate is skipped (Outcome A) or fires (Outcome B — acceptable).
- **Stand up `vault/detections/`**: directory + `_template.md` + `README.md` (coverage index) + `t1059-001-powershell-encoded.md` (the worked example, populated).
- **Update `vault/CLAUDE.md`** to document the new `vault/detections/` slot in the schema's table.
- **Update `vault/architecture/components/splunk.md`** with the new saved search and the Sysmon sourcetype/source distinction.
- **Create `vault/architecture/components/sysmon.md`** as a new component page with: what Sysmon is, where it runs in the lab, configuration source (SwiftOnSecurity), Sysmon EventCode reference table (high-yield codes only), Sysmon field reference table, "why source= not sourcetype= filters" gotcha, smoke-test queries, references to upstream docs.
- **Runbook** at `vault/subprojects/2026-04-30-detection-foundations/runbook.md` covering: Sysmon install, Universal Forwarder edit, ART install, the "run a technique" loop, VMware Workstation snapshot discipline, "what to do if Splunk hits the daily license cap," diagnostic checks, security-posture note (Defender off, C: drive excluded — intentional lab setup), the worked example as the smoke-test template, the standby system-prompt-addendum fix, and the **5–7 starter SPL queries by observation question** (each annotated).
- **Observation toolkit split:** procedural starter SPL queries live in the runbook; long-lived reference catalogs (EventCode table, field reference table) live in `vault/architecture/components/sysmon.md` so future sub-projects (B EDR layer, C detection-at-scale, H purple team) have a single canonical Sysmon reference page.
- **Log entry** at vault root marking D1 complete.

### Out of scope (deliberately deferred)

- **Pre-writing SPL or saved searches for techniques the user hasn't run.** Speculation. New techniques get documented as the user runs them; their pages start with `status: untested` and accumulate observations.
- **Sysmon config tuning.** No edits to SwiftOnSecurity's XML in D1. If volume becomes a problem, that's a discrete post-D1 ticket with concrete data driving it.
- **AI base64-decoding of the encoded PowerShell payload.** Architecturally interesting but pulls A1 prompt/schema work into D1; defers as "D1.5" extension hook. Captured as Outcome B variance: *if* Claude decodes naturally without prompt changes, fine; we don't engineer for it.
- **System prompt addendum** for Sysmon-shaped alerts. Reactive only — runbook documents the one-paragraph addendum as a standby fix if Claude misbehaves on the worked example. Not in D1's default scope.
- **Sigma rule format / detection-as-code conversion.** Sub-project C. D1 ships hand-written SPL.
- **Automated/scheduled ART runs (purple team continuous validation).** Sub-project H. D1 ships the manual runbook version.
- **EDR layer** (LimaCharlie, Velociraptor). Sub-project B.
- **Multi-endpoint Sysmon deployment.** Single Windows 10 VM only.
- **Defender being off as a permanent posture decision.** It's the current lab state per user; we document it but D1 doesn't re-litigate the choice.
- **Splunk free-tier license replacement.** D1 lives within 500MB/day. If that becomes the binding constraint, that's its own discrete decision (paid Splunk vs. ELK migration vs. usage-discipline) — not a D1 question.

## Approach

D1's architecture is shaped by four locked decisions from the brainstorm (2026-04-30):

1. **Reuse the existing webhook; gate-skipped path expected.** No new n8n workflow, no new webhook endpoint, no n8n node changes. The new Sysmon-driven saved search posts to the same v2 production webhook URL the brute-force search already targets. Claude triages whatever lands. Because Sysmon process-create events have no network IOCs structurally, A1's `iocs_enriched` filter returns empty, A2's gate skips, Slack posts a plain alert. Architecturally this is A2's Test 1 path running on Sysmon data.
2. **T1059.001 as the worked example, not the centerpiece.** The foundation (Sysmon + ART + observation toolkit) is the durable deliverable. T1059.001 is the integration test that proves the SOAR pipeline accepts a Sysmon-shaped alert. Future techniques are a runbook routine, not new sub-projects.
3. **SwiftOnSecurity off-the-shelf, no edits.** The de-facto SOC-lab default. Tuning happens after we observe what's noisy in *our* environment, not before.
4. **Manual ART invocation, no harness.** Manual run + manual Splunk observation IS the learning loop. Automating it away defeats the user's stated goal.

Rejected alternatives (from brainstorm):

- **AI base64-decoding the encoded payload (Option B from Q1).** Would extract IOCs from inside the encoded blob, fire the gate, exercise the gated path. Architecturally interesting but couples D1 to A1's prompt and adds a "Claude decodes payloads" sub-project inside D1. Defers as D1.5 hook. (Note: if Claude decodes naturally during live-fire, that's Outcome B — accepted as bonus variance, not engineered for.)
- **Olaf Hartong's modular Sysmon config.** More sophisticated, but requires choosing which modules to load — a meta-decision that depends on knowing what techniques you'll run, which the user explicitly said they don't yet know.
- **Custom Sysmon config built from defaults.** Hand-rolled exclusions are their own engineering project; not interview-canonical.
- **A harness wrapping `Invoke-AtomicTest`** (e.g., a PowerShell script that captures Splunk-event-counts pre/post-run). Suppresses the manual-observation step that IS the learning.
- **Scheduled ART runs via Windows Task Scheduler.** Sub-project H's deliverable; including in D1 would be direct creep.
- **A new webhook endpoint / parallel SOAR mini-pipeline.** Doesn't exercise the existing pipeline as the SOAR-integration test the bootstrap calls for.
- **A second MITRE technique in D1's worked-example scope.** Violates the "ship a small loop end-to-end first" principle; turns D1 into a coverage-map sub-project (which is C).

## Design

### 1. Architecture overview / data path

D1's architecture has a clear split between **generation** (analyst causes something to happen on the Windows VM) and **detection/response** (Splunk catches it, optionally fires the SOAR pipeline). The runbook serves both halves:

- **Generation half** — manual. Analyst SSH-/RDP-into the Windows VM, runs `Invoke-AtomicTest <T-id>`, observes.
- **Detection/response half** — split into two paths:
  - **Manual exploration** — alt-tab to Splunk's Search & Reporting bar; use observation-toolkit SPL to find what happened. Works for *any* technique. No automation.
  - **Automated detection** — for T1059.001 specifically, a saved search fires on a 5-minute cron, posts to the existing v2 webhook, traverses the existing SOAR pipeline. Works for *one* technique (the worked example). Future techniques become automated only when the analyst hand-writes a saved search for them — a runbook routine.

#### Data flow (end-to-end)

```
┌─────────────────────────────────────────────────────────────────┐
│ Windows 10 VM                                                    │
│                                                                  │
│  ┌───────────────────┐     ┌──────────────────────────────────┐ │
│  │ Atomic Red Team   │     │ Sysmon                  [NEW]    │ │
│  │ [NEW]             │ ──▶ │  (SwiftOnSecurity config,        │ │
│  │ Invoke-AtomicTest │     │   off-the-shelf)                 │ │
│  └───────────────────┘     │                                  │ │
│                            │ Writes events to Windows         │ │
│                            │ Event Log channel:               │ │
│                            │ Microsoft-Windows-Sysmon/        │ │
│                            │ Operational                      │ │
│                            └──────────────────┬───────────────┘ │
│                                               │                 │
│  ┌────────────────────────────────────────────▼───────────────┐ │
│  │ Splunk Universal Forwarder       [EXISTING — config edit]  │ │
│  │                                                            │ │
│  │ inputs.conf: add stanza for Sysmon channel                 │ │
│  │ Existing stanzas (Security/Application/System) untouched   │ │
│  │                                                            │ │
│  │ Forwards over 9997/tcp to 192.168.129.131                  │ │
│  └────────────────────────┬───────────────────────────────────┘ │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ Splunk Enterprise (192.168.129.131)        [EXISTING + edits]   │
│                                                                  │
│ Index: mydfir-project (unchanged — Sysmon events land here      │
│   alongside the existing Windows Security/App/System events)    │
│                                                                  │
│ Sourcetype: XmlWinEventLog (existing) — Sysmon events come in   │
│   under source="WinEventLog:Microsoft-Windows-Sysmon/           │
│   Operational" inside that sourcetype                           │
│                                                                  │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Search & Reporting          [observation toolkit lives     │  │
│ │                              here as documented SPL]       │  │
│ │   Manual queries from runbook (any technique)              │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Saved Searches                                             │  │
│ │   • Test-Brute-Force-External-Spoofed (existing, disabled) │  │
│ │   • T1059.001 - PowerShell Encoded Command  [NEW]          │  │
│ │       cron */5 * * * *, dispatch.alert.track=1,            │  │
│ │       webhook → v2 production URL                          │  │
│ └────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────┘
                                     │ webhook (T1059.001 only)
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ n8n SOC Triage v2 (192.168.129.132)             [UNCHANGED]     │
│                                                                  │
│ Webhook ──▶ Anthropic (Claude) ──▶ Extract Triage Result        │
│   ──▶ Create Iris Alert (alert_iocs:[] expected for Sysmon)     │
│   ──▶ Has Malicious IOCs? IF                                    │
│        └─ FALSE branch (gate-skipped, expected)                 │
│           ──▶ Post Slack Alert (plain, no buttons)              │
│           ──▶ END                                               │
└────────────────────────────────────┬────────────────────────────┘
                                     │
                          ┌──────────┴──────────┐
                          ▼                     ▼
                    ┌──────────┐         ┌────────────┐
                    │ Slack    │         │ DFIR-Iris  │
                    │ #alerts  │         │ alert      │
                    │ [plain]  │         │ (no case)  │
                    └──────────┘         └────────────┘
```

#### What's NEW vs EXISTING

| Component | Status | Change |
|---|---|---|
| Sysmon on Windows VM | **NEW** | Install via SwiftOnSecurity config |
| ART on Windows VM | **NEW** | Bootstrap install + atomics |
| Universal Forwarder install | EXISTING | No change |
| Universal Forwarder `inputs.conf` | EDIT | Add stanza for Sysmon channel |
| Splunk index `mydfir-project` | EXISTING | No change (Sysmon events join it) |
| Splunk sourcetype `XmlWinEventLog` | EXISTING | No change |
| Saved search: brute-force | EXISTING (disabled) | No change |
| Saved search: T1059.001 | **NEW** | Create + activate |
| n8n SOC Triage v2 workflow | EXISTING | **NO change** (load-bearing — A1/A2 untouched) |
| Anthropic system prompt | EXISTING | **NO change in default scope** (reactive fix only if Claude misbehaves) |
| Iris alert ingestion | EXISTING | No change (alerts with `alert_iocs:[]` expected) |
| Slack `#alerts` channel | EXISTING | No change |
| Vault directory `vault/detections/` | **NEW** | Create + template + index + worked-example page |
| Vault `architecture/components/splunk.md` | EXISTING | EDIT (document new saved search + Sysmon sourcetype) |
| Vault `CLAUDE.md` schema table | EXISTING | EDIT (add `vault/detections/` row) |

#### The architectural promise

A T1059.001 alert is functionally identical to A2's Test 1 (internal brute force, gate-skipped path). Different fields, different triage content, but the workflow path through n8n is the same: webhook → Claude → Iris alert created with empty `alert_iocs` → IF goes to false branch → plain Slack post → end. **A2 already validated this branch end-to-end** (Phase 10 Test 1). D1's worked-example validation is therefore not "test a new path" but "test that an existing-and-validated path also accepts a new alert family." Lower-risk validation than it sounds.

The risk concentrates entirely in Claude's behavior on the unfamiliar payload shape. If Claude returns a schema-compliant response with `iocs_enriched: []` (or with IOCs it pulled from elsewhere in the alert that happen to be present), the rest of the pipeline doesn't care that the alert is from Sysmon. If Claude returns something malformed, A1's `Extract Triage Result` Code node throws (existing diagnostic) and the workflow fails visibly in n8n executions — not silently. The failure mode is loud and locally diagnosable.

### 2. Components

#### 2.1 Sysmon (NEW)

- **Source:** `https://github.com/SwiftOnSecurity/sysmon-config`, file `sysmonconfig-export.xml`, downloaded from the `master` branch with the commit SHA recorded in the runbook at install time.
- **Sysmon binary:** Sysinternals' official `Sysmon64.exe` (current version at install time recorded in runbook).
- **Install command (admin PowerShell):** `Sysmon64.exe -accepteula -i sysmonconfig-export.xml`
- **No edits to the XML.** Upstream-flow preserved. Tuning is post-D1.
- **Verification:** open admin cmd, run `notepad.exe`, confirm Splunk shows an EventCode=1 event for it within ~60 seconds via the observation-toolkit query.
- **Channel written to:** Windows Event Log channel `Microsoft-Windows-Sysmon/Operational` — the channel the Universal Forwarder must pick up.

#### 2.2 Splunk Universal Forwarder configuration (EDIT existing)

- **Method:** hand-edit `inputs.conf` on the Windows VM directly. The vault doesn't currently track a deployment server, and standing one up for one config change is scope creep.
- **Path (Phase 0 verifies):** typically `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` — the `local` directory wins over `default`.
- **Stanza added:**
  ```ini
  [WinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled = 0
  index = mydfir-project
  renderXml = true
  ```
- **`renderXml = true`** is intentional: keeps Sysmon events as structured XML, which Splunk's Add-on for Microsoft Windows parses into searchable fields. Matches the existing Security-channel ingestion pattern.
- **Restart:** Splunk Universal Forwarder service after the edit (`Restart-Service SplunkForwarder` from admin PowerShell). Without restart, the new stanza isn't loaded.
- **Verification:** Same as 2.1's verification — `notepad.exe` produces an event visible in Splunk.

#### 2.3 Atomic Red Team (NEW)

- **Install command (admin PowerShell, executed once):**
  ```powershell
  Set-ExecutionPolicy Bypass -Scope CurrentUser
  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics
  ```
- **Module:** `Invoke-AtomicRedTeam` PowerShell module installed to the user's WindowsPowerShell Modules directory.
- **Atomics library:** YAML technique catalog under `C:\AtomicRedTeam\atomics\`. Each technique is a folder named after its T-id with a YAML file describing the test cases.
- **Run pattern (manual, runbook-documented):**
  ```powershell
  Import-Module Invoke-AtomicRedTeam
  Invoke-AtomicTest T1059.001 -ShowDetailsBrief                    # preview
  Invoke-AtomicTest T1059.001 -TestNumbers 2                       # execute
  Invoke-AtomicTest T1059.001 -TestNumbers 2 -Cleanup              # cleanup
  ```
- **No harness.** Manual run, manual observation. The point is to learn what each test does by reading `-ShowDetailsBrief` output before running.
- **VMware Workstation snapshot discipline (runbook):** before any ART session, take a snapshot of the Windows VM (VM → Snapshot → Take Snapshot). After the session, optionally revert. Cleanup commands aren't always perfect; the snapshot is the safety net.

#### 2.4 Splunk index / sourcetype handling (EXISTING with note)

- **Index:** `mydfir-project` — Sysmon events land alongside the existing Windows Security/App/System events. No new index.
- **Sourcetype:** Splunk's Add-on for Microsoft Windows assigns `XmlWinEventLog` as the sourcetype for Sysmon's Operational channel (same as Security/App/System). Differentiating is by `source=` (the channel name), not `sourcetype=`.
- **Search-time field extraction:** the Add-on parses Sysmon's XML structured events into searchable fields (`Image`, `CommandLine`, `ParentImage`, `User`, `ProcessId`, etc.) automatically. No `props.conf`/`transforms.conf` needed.
- **Phase 0 unknown to verify:** confirm field extraction works as expected on the first ingested Sysmon event. If fields don't auto-extract, install Splunk Add-on for Microsoft Sysmon (free Splunk app) — small additional task, runbook-documented as a contingency.

#### 2.5 SPL detection for T1059.001 (NEW — annotated)

The query, then per-clause annotation:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)\s-e[ncodedommand]*\s"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents
        by _time, host, User, Image
```

| Clause | What it does |
|---|---|
| `index=mydfir-project` | Narrows the search to the project's index. Searching without an `index=` clause is the #1 SPL beginner mistake — it scans every index Splunk knows about, which is slow and expensive. |
| `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | Restricts to events from Sysmon's channel. Excludes Windows Security/App/System events landing in the same index/sourcetype. |
| `EventCode=1` | Sysmon's Process Create event. Sysmon assigns numeric EventCodes to event types; 1 is process creation. |
| `Image="*\\powershell.exe"` | The Image field holds the full path to the executable. The `\\` escapes the backslash; `*\\powershell.exe` matches `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and 32-bit equivalents. |
| `\|` | The pipe — SPL pipelines pass the result of one stage to the next. Same idea as a Unix shell pipe. |
| `regex CommandLine="..."` | The `regex` command filters events whose CommandLine field matches a regular expression. Stricter than wildcard `*-enc*` matching because it anchors on PowerShell's actual flag syntax. |
| `(?i)` | Inline regex flag — case-insensitive matching. PowerShell's parser is case-insensitive for flag names. |
| `\s-(en?c\|encodedcommand)\s` | Whitespace-boundary on both sides; matches `-e`, `-en`, `-enc`, or `-encodedcommand` as a flag (not as a substring of some other word). The `?` makes the `n` optional. |
| `\| stats count, values(...) as ... by ...` | The aggregation stage. `count` counts matching events; `values(field) as alias` collects unique values of `field` into a multi-valued column named `alias`; `by _time, host, User, Image` groups results by those fields. |

**What the analyst sees:** for each (timestamp, host, user, image) bucket, a count of encoded-PowerShell events plus the unique CommandLines and parent processes that fired. ParentImage is the high-signal column — `winword.exe` or `outlook.exe` would scream "phishing macro launched PowerShell," while `cmd.exe` from a logged-in admin user is benign.

**Why this depth:** demonstrates `regex`, `stats by`, `values()` — three of the most commonly-asked SPL patterns in interviews. Avoids decoding the base64 payload in SPL (preserves division of labor — Claude can do that on the n8n side later if we ever want).

#### 2.6 Splunk saved search (NEW)

| Field | Value |
|---|---|
| Name | `T1059.001 - PowerShell Encoded Command` |
| Search | The SPL from 2.5, exactly |
| Alert type | Scheduled |
| Time Range | `Last 24 hours` (matches existing `Test-Brute-Force-External-Spoofed` saved search; Splunk's "For each result" deduplication handles repeated results across cron ticks) |
| Cron Expression | `*/5 * * * *` (every 5 minutes — standard SOC cadence; the brute-force search's `* * * * *` was a test-cycle value, not production) |
| Expires | `24 hour(s)` |
| Trigger alert when | Number of Results is greater than 0 |
| Trigger | For each result |
| Throttle | Unchecked (no throttle) |
| Trigger Actions | Webhook **+** Add to Triggered Alerts |
| Webhook URL | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` (existing v2 production URL) |

**Why 24-hour window with 5-minute cron doesn't duplicate-fire:** Splunk's scheduled-alert "For each result" trigger tracks each result row's content hash and dedupes across cron ticks — the same row appearing in subsequent search runs does *not* re-fire the alert action. The 24-hour window provides a wide look-back so late-indexed events are still detected; the 5-minute cron provides standard SOC reaction time; the result-hash dedup prevents overfire. The brute-force search uses the same Time Range + dedup pattern (with a `* * * * *` test cron); D1 keeps the Time Range and shifts cron to `*/5` as the production-shape default.

**"Add to Triggered Alerts"** is Splunk's internal triggered-alerts dashboard tracking — useful for debugging "did the alert fire?" without inspecting n8n logs. Mirrors the brute-force search's configuration exactly.

The webhook payload Splunk sends is a single JSON object containing `result` (the row from the search output) plus alert metadata (`search_name`, etc.). The existing pipeline reads `result.search_name` and treats the rest of `result` as the alert body Claude triages.

#### 2.7 n8n integration (UNCHANGED — verification only)

- **No node changes** to SOC Triage v2.
- **System prompt unchanged in default scope.** The runbook documents the standby fix (one-bullet addendum about Sysmon-shaped alerts) if Claude misbehaves on the worked example.
- **Verification points** during the live-fire test (Section 3):
  - Webhook fires with the saved-search payload.
  - Claude returns a schema-compliant response (severity, iocs_enriched, etc.).
  - Iris alert is created (with `alert_iocs: []` expected — Sysmon process-create has no network IOCs by default).
  - `Has Malicious IOCs?` IF takes the FALSE branch (gate-skipped path, matching A2's Test 1).
  - Slack `#alerts` shows a plain alert post (no buttons).
  - Workflow execution completes within A2's 2100s timeout.
- **Acceptable variance:** Claude *might* extract IOCs from elsewhere in the alert payload (Outcome B). If the gate fires as a result, that's a *bonus* validation, not a failure — runbook documents either outcome.

#### 2.8 Vault catalog structure (NEW)

```
vault/
└── detections/
    ├── README.md           # coverage index — markdown table
    ├── _template.md        # copy-this-to-add-a-technique
    └── t1059-001-powershell-encoded.md   # worked example
```

**`README.md`** — one-paragraph overview + a coverage table:

| Technique ID | Tactic | Status | Last Run | Page |
|---|---|---|---|---|
| T1059.001 | Execution | saved-search-active | 2026-04-30 | `[t1059-001-powershell-encoded](t1059-001-powershell-encoded.md)` |

The `Status` column uses the lifecycle: `untested` → `observed` → `spl-drafted` → `saved-search-active`.

**`_template.md`** — copy-this skeleton:

```markdown
---
status: untested
technique_id: T<id>
tactic: <Initial Access / Execution / Persistence / ... >
last_run: YYYY-MM-DD
related: [[../subprojects/2026-04-30-detection-foundations/runbook]]
---

# T<id> — <name>

## Description
<one paragraph: what the technique is and why it matters>

## ART command
<exact Invoke-AtomicTest invocation>
<cleanup>

## Observations
<Sysmon EventCodes seen, fields populated, surprises>

## SPL
<the search you wrote, annotated inline; or "(none yet)">

## Saved search
<name + cron + webhook target; or "(none yet)">

## Notes
<false positives, parent-process patterns, tuning observations>
```

**`t1059-001-powershell-encoded.md`** — populated example, written during D1's implementation. Status starts as `untested`, advances through `observed` → `spl-drafted` → `saved-search-active` as each phase of the implementation plan completes. Final state at D1 close: `saved-search-active`.

#### 2.9 Observation toolkit (NEW — split between runbook + component page)

The "run any technique, observe what happened" learning loop needs two kinds of content: **procedural** (queries you copy-paste into Splunk) and **referential** (lookup tables for what an EventCode means or which field carries which data). D1 splits these into the two natural homes:

**In `runbook.md` — procedural** (5–7 starter SPL queries, each annotated inline):

1. *"What just ran?"* — recent process creates (EventCode=1).
2. *"What network connections happened?"* — recent EventCode=3 with `DestinationIp`, `DestinationPort`, `Image` columns.
3. *"What files got written?"* — recent EventCode=11 with `TargetFilename`, `Image`.
4. *"Did anything modify the registry?"* — recent EventCode IN (12, 13, 14) with `TargetObject`, `Image`.
5. *"What DNS lookups happened?"* — recent EventCode=22 with `QueryName`, `Image`.
6. *"What's the process tree for PID X?"* — recent events where `ProcessId=X OR ParentProcessId=X`, sorted by `_time`.
7. *Meta query: "What Sysmon EventCodes have I received in the last hour?"* — `... | stats count by EventCode | sort -count` — confirms the config is capturing what you expect.

Each query is annotated inline so the user (currently learning SPL) can read why each clause is there.

**In `vault/architecture/components/sysmon.md` — referential.** EventCode reference table + field reference table. See Section 2.10 below for the component page's full structure.

The split mirrors the precedent set by A2: A2's runbook held the procedural escalate/deny/timeout instructions, but Iris's IOC-type-ID catalog and severity-ID catalog live in `vault/architecture/components/dfir-iris.md` because they're long-lived reference content. Component pages get re-read in every future Iris-touching session; A2's runbook gets re-read mostly during A2's own lifecycle.

#### 2.10 Sysmon component page (NEW)

`vault/architecture/components/sysmon.md` — new vault page, follows the existing component-page pattern from `splunk.md` and `dfir-iris.md`. Contains:

- **Frontmatter** — `status: active`, `updated: <install date>`, `related: [[../current-state]], [[splunk]], [[../../subprojects/2026-04-30-detection-foundations/runbook]]`.
- **What it is** — one paragraph: Sysmon is Sysinternals' Windows system service that logs detailed process/file/network/registry telemetry to a dedicated Windows Event Log channel; supplements (does not replace) the native Security/App/System logs.
- **Where it runs** — Windows 10 VM (192.168.129.x captured during D1 Phase 0); service name `Sysmon64`; channel `Microsoft-Windows-Sysmon/Operational`; ingested by the existing Splunk Universal Forwarder (forwarder config edit per 2.2); lands in Splunk under `index=mydfir-project sourcetype=XmlWinEventLog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.
- **Configuration table** — config source (SwiftOnSecurity/sysmon-config master branch, commit SHA captured at install), config file (`sysmonconfig-export.xml` off-the-shelf, no edits), Sysmon binary version, hash algorithms enabled.
- **EventCode reference table** (high-yield codes the SwiftOnSecurity config captures):

  | EventCode | Name | When it fires |
  |---|---|---|
  | 1 | Process Create | A new process is launched |
  | 3 | Network Connect | A process initiates a network connection |
  | 7 | Image Loaded | A DLL or driver is loaded into a process |
  | 10 | Process Access | A process opens a handle into another process (LSASS pivot for credential dumping) |
  | 11 | File Create | A file is written to disk |
  | 12 / 13 / 14 | Registry events | Registry key created / value set / key renamed |
  | 22 | DNS Query | A DNS lookup is performed |
  | 23 | File Delete | A file is deleted |

- **Field reference table** (high-frequency Sysmon fields):

  | Field | Meaning |
  |---|---|
  | `_time` | Splunk-assigned event timestamp |
  | `Image` | Full path to the executable |
  | `CommandLine` | Command-line string the process was invoked with |
  | `ParentImage` / `ParentCommandLine` | The same for the parent process |
  | `ProcessId` / `ParentProcessId` | PIDs |
  | `User` | Account context the process ran under |
  | `Hashes` | MD5 / SHA1 / SHA256 / IMPHASH of the executable |
  | `TargetFilename` | (EventCode 11/23) the file path being created or deleted |
  | `TargetObject` | (EventCode 12-14) the registry key or value path |
  | `QueryName` | (EventCode 22) the DNS name being looked up |
  | `DestinationIp` / `DestinationPort` | (EventCode 3) the network connection target |

- **"Why `source=` (not `sourcetype=`) is the channel filter"** — short note: Splunk Add-on for Microsoft Windows assigns the same sourcetype (`XmlWinEventLog`) to all Windows Event Log channels. Sysmon's channel differentiates by the `source=` field, not `sourcetype=`. Future SPL queries against Sysmon should use `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.
- **How to verify it's working** — the `notepad.exe` smoke test + EventCode coverage check.
- **References** — links to Microsoft's Sysmon docs and SwiftOnSecurity's repo, plus a back-link to D1's README and to splunk.md.

Page size estimate: ~80–120 lines. Created during D1 implementation alongside the install steps.

### 3. Worked example: T1059.001 end-to-end

A concrete walkthrough so the design intent is unambiguous. Everything below assumes the implementation plan has shipped (Sysmon installed, ART installed, saved search active). This is the *live-fire validation* run.

A few details below are uncertainty-tagged with **(Phase 0 verifies)** — the exact ART test number and the precise Sysmon field shape are confirmed during Phase 0 of the implementation plan.

#### 3.1 The trigger — analyst runs ART

User accesses the Windows 10 VM (SSH or RDP), opens admin PowerShell, takes a VMware Workstation snapshot, runs:

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -TestNumbers 2 -ShowDetailsBrief    # preview
Invoke-AtomicTest T1059.001 -TestNumbers 2                      # execute
```

ART's Test 2 of T1059.001 (**Phase 0 verifies the exact test number / payload**) launches `powershell.exe` with an `-EncodedCommand` flag whose base64 payload is a short benign command. No malware on disk; no Defender interaction (Defender is off anyway).

#### 3.2 What Sysmon captures

The `powershell.exe` invocation produces an EventCode=1 (Process Create) event in the `Microsoft-Windows-Sysmon/Operational` channel. Key fields populated (typical shape — Phase 0 verifies exact field names):

| Field | Example value |
|---|---|
| `EventCode` | `1` |
| `_time` | `2026-04-30T18:42:13` (Sysmon-stamped) |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | `powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAg...` |
| `ParentImage` | The ART runner's process |
| `ParentCommandLine` | The ART runner's invocation |
| `User` | `WIN10VM\<account>` |
| `ProcessId` | (some integer) |
| `Hashes` | MD5/SHA256 of `powershell.exe` (whether populated depends on SwiftOnSecurity's `<HashAlgorithms>` block — Phase 0 verifies) |

#### 3.3 What Splunk receives

The Universal Forwarder ships the event over 9997/tcp to `192.168.129.131`. Splunk indexes it under:

- `index = mydfir-project`
- `sourcetype = XmlWinEventLog`
- `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

Splunk Add-on for Microsoft Windows extracts structured Sysmon fields into searchable form. (Phase 0 verifies field extraction works on the first ingested event.)

#### 3.4 The saved search detects

Within ~5 minutes (5-minute cron — standard SOC cadence), the `T1059.001 - PowerShell Encoded Command` saved search runs (SPL from 2.5). The event matches: `Image` ends in `powershell.exe`, the `regex` matches `-EncodedCommand` (case-insensitive, whitespace-bounded). `stats` produces one result row. `count > 0` triggers the saved search's webhook action.

#### 3.5 The webhook payload to n8n

Splunk POSTs a JSON object to the v2 production webhook URL. Approximate shape (Phase 0 verifies exact schema):

```json
{
  "result": {
    "_time": "2026-04-30T18:42:13",
    "host": "WIN10VM",
    "User": "WIN10VM\\...",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "count": "1",
    "command_lines": "powershell.exe -EncodedCommand Vwby...",
    "parents": "..."
  },
  "search_name": "T1059.001 - PowerShell Encoded Command",
  "results_link": "http://mydfir-splunk:8000/...",
  ...
}
```

#### 3.6 What Claude triages

n8n's `Webhook` node receives the payload. The `Message a model` node sends Claude a user message — the JSON-stringified webhook body, exactly as A1 set it up. Claude triages and returns a schema-compliant tool call to `submit_triage_result`. **Two acceptable outcomes:**

**Outcome A (expected — gate-skipped):** Claude flags the command-line as suspicious behavior (encoded PowerShell is a classic obfuscation indicator), assigns severity `medium` or `high`, populates `iocs_enriched: []` (no IPs/domains/hashes are present in the alert structurally), and writes investigation notes about command-line obfuscation. The gate skips because the filtered IOC list is empty.

**Outcome B (acceptable bonus — gate-fired):** Claude decodes the base64 payload itself, finds something inside that looks like an IOC (e.g., a URL, an IP literal, a domain), populates `iocs_enriched` with that, and the gate fires.

Both outcomes are validation-positive. Outcome A confirms the gate-skipped path on Sysmon data (the primary architectural promise). Outcome B confirms Claude's decoding capability and the gated path on Sysmon data.

#### 3.7 The Iris alert

A1's `Extract Triage Result` Code node + `Create Iris Alert` HTTP node produce an Iris alert. Title: `T1059.001 - PowerShell Encoded Command`. Severity per Claude. Description follows A1's template (Splunk URL, host, user, summary). `alert_iocs` is `[]` for Outcome A (or one IOC for Outcome B).

The Iris alert lands in Iris's alert queue at `https://192.168.129.133/alerts`.

#### 3.8 The gate

`Has Malicious IOCs?` IF node evaluates `alert_iocs.length > 0`:

- **Outcome A:** `0 > 0` is false → FALSE branch → plain Slack post → END. **A2's Test 1 path running on Sysmon data — integration test passes.**
- **Outcome B:** `1 > 0` is true → TRUE branch → Slack with Approve/Deny buttons → analyst decides → escalate or deny. Same path A2's Test 2 ran. The user gets to decide whether to Approve (creates an Iris case) or Deny (alert stays in queue) — runbook recommends Deny for a known test event unless the case is wanted for documentation.

#### 3.9 What lands in Slack

For Outcome A — a plain message in `#alerts` (no buttons), looking like A2's Test 1 Slack post. Title, severity badge, summary, "View in Splunk" link. Thread is empty (no decision needed).

For Outcome B — A2's full Approve/Deny gate message, exercised against a Sysmon-source alert for the first time.

#### 3.10 What lands back in the vault

After the run, the user updates `vault/detections/t1059-001-powershell-encoded.md`:

- `last_run` field updated to today's date.
- **Observations** section gains a paragraph: "ART Test 2 fired one EventCode=1 event with `Image=...\powershell.exe` and `CommandLine` containing the `-EncodedCommand` substring. Sysmon captured CommandLine + ParentImage as expected. Splunk indexed within ~60s. Saved search fired on next cron tick."
- **Notes** section gains an entry recording which outcome occurred (A or B) and any surprises.

The runbook also documents this exact sequence as the smoke test for any future technique-page reaching `status: saved-search-active`.

#### 3.11 What this run actually validates

After this single end-to-end run, the following are demonstrable:

1. Sysmon installed, configured, and emitting events to the channel SwiftOnSecurity covers.
2. The Universal Forwarder picks up the Sysmon channel.
3. Splunk indexes Sysmon events under the project index with field extraction working.
4. A hand-written SPL search detects the technique correctly (regex flag-match works on real CommandLine values).
5. A Splunk saved search reliably triggers the existing v2 webhook on a 5-minute cron.
6. The existing SOAR pipeline (Claude triage → Iris alert → IF gate → Slack post) accepts a Sysmon-shaped payload without n8n changes.
7. The gate-skipped path (or the gated path, depending on Outcome) runs end-to-end on Sysmon data.
8. The vault catalog page captures the run as documented evidence.

Any one of those failing in the live-fire run is a discoverable, locally-debuggable problem. None of them require A1/A2 changes to fix; failures isolate to Sysmon, the forwarder config, the SPL, the saved search, or the system prompt — all D1-owned surfaces.

## Validation strategy

D1 doesn't fit A1/A2's "pinned-data test cases" pattern cleanly. A1/A2 had multiple branching paths through the workflow that needed isolated verification — pinned data was the right tool. D1's verification is shaped differently: most of the surface is *infrastructure setup* (Sysmon installed, forwarder forwarding, ART runnable), and the integration test is a single live-fire sequence. Three verification tiers:

**Tier 1 — Infrastructure smoke tests** (after each install step, before the worked example):

1. *Sysmon producing events.* Spawn `notepad.exe` from admin cmd on the Windows VM. Within 60 seconds, `index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\notepad.exe"` returns ≥1 event. Validates Sysmon install + forwarder config + Splunk ingestion + field extraction in one shot.
2. *Sysmon EventCode coverage check.* The meta query from the observation toolkit: `... | stats count by EventCode | sort -count`. Confirms which EventCodes the SwiftOnSecurity config is producing in the lab — useful baseline for any future "why didn't I see X?" debugging.
3. *ART runnable.* `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` returns the test catalog without errors.

**Tier 2 — Worked-example live-fire** (the integration test from Section 3):

4. *T1059.001 end-to-end.* `Invoke-AtomicTest T1059.001 -TestNumbers 2`, observe Splunk indexing, verify the saved search fires on next cron tick, verify the webhook lands at n8n, verify Claude triages and Iris alert is created, verify the IF gate behavior matches Outcome A or B per Section 3.

**Tier 3 — Catalog page lifecycle** (documentation correctness):

5. *Catalog page progresses through statuses.* `t1059-001-powershell-encoded.md` reaches `status: saved-search-active` with all sections populated by the time D1 closes. Coverage-index README reflects it.

No pinned-data tests for D1. The infrastructure smoke tests + live-fire worked example are the verification.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Splunk free-tier 500MB/day cap hit during ART runs | Medium | Indexer rejects new events for the rest of the day | Runbook documents pre-flight license check; cap-hit is recoverable (wait until tomorrow); not a data-loss event for a lab |
| Claude misbehaves on Sysmon-shaped alert (returns malformed response) | Low-medium | A1's `Extract Triage Result` throws → workflow fails visibly in n8n executions | Standby fix: one-paragraph addendum to system prompt for process-create alert family; runbook documents the addendum |
| SwiftOnSecurity config excludes an event the worked example expects | Low | Saved search never fires; "ran ART, no Splunk event, no alert" | Tier-1 smoke tests catch this before live-fire; isolation is fast (`notepad.exe` test) |
| Splunk's saved-search webhook serialization differs from A1's expected shape | Low-medium | Claude sees an unfamiliar wrapper; triage may degrade | Phase 0 inspects an actual webhook payload before relying on its shape |
| Universal Forwarder config edit doesn't take effect (service not restarted, file path wrong) | Medium | No Sysmon events reach Splunk | Tier-1 smoke test #1 surfaces it immediately; runbook documents the restart step |
| ART test residue persists after `-Cleanup` | Medium | Future test runs behave oddly | VMware Workstation snapshot before each ART session; revert if needed |
| Defender-off security posture surprises a future-fresh-instance reader | Low | Confused investigation of "why did this work?" | Runbook explicitly documents the posture as intentional lab setup, not an oversight |
| `vault/detections/` directory becomes stale (user runs techniques but doesn't update pages) | Medium | Catalog drifts from reality | Runbook frames the page-update as part of the run-a-technique routine, not a separate chore |
| Field extraction for Sysmon's XML doesn't auto-work in this Splunk install | Low | SPL `Image=`/`CommandLine=` filters return empty | Phase 0 inspects an actual ingested event in `_raw`; if extraction fails, install Splunk Add-on for Microsoft Sysmon (free) |
| SSH access to Windows VM fails or lacks admin context | Low | Install steps fall back to the user RDP'ing in and running commands by hand (the A1/A2 pattern) | Phase 0 verifies SSH; fallback to manual is acceptable, just slower |
| Splunk's "For each result" hash-dedup behaves differently for Sysmon-shaped result rows than for brute-force result rows | Low | If dedup misses, same event fires N webhooks across the 24-hour window; if dedup over-aggregates, repeated ART runs at different times collapse into one webhook | Phase 0 observes the live-fire behavior — runs ART twice with a few-minute gap and confirms two distinct webhooks land; if dedup misbehaves, narrow Time Range to a smaller window (e.g., `Last 5 minutes`) or add throttle |

## Success criteria

D1 is "done" when all of these are satisfied:

1. [ ] Sysmon installed on the Windows 10 VM with SwiftOnSecurity's `sysmonconfig-export.xml` (off-the-shelf, no edits); upstream commit SHA recorded in runbook.
2. [ ] Splunk Universal Forwarder's `inputs.conf` includes the Sysmon channel stanza; service restarted; Tier-1 smoke test #1 passes.
3. [ ] Tier-1 smoke test #2 (EventCode coverage check) produces a non-trivial distribution of Sysmon EventCodes — confirms config is actually emitting.
4. [ ] Atomic Red Team installed on the Windows 10 VM; Tier-1 smoke test #3 passes.
5. [ ] SPL detection for T1059.001 written and verified manually in Splunk Search & Reporting against a real `Invoke-AtomicTest T1059.001` event.
6. [ ] Splunk saved search `T1059.001 - PowerShell Encoded Command` created, active, scheduled `*/5 * * * *` (every 5 minutes), Time Range `Last 24 hours`, Trigger `For each result`, webhook URL = v2 production URL.
7. [ ] Tier-2 live-fire run produces an Iris alert + Slack post matching either Outcome A (gate-skipped) or Outcome B (gated). Runbook records which outcome occurred.
8. [ ] `vault/detections/` directory exists with `README.md` (coverage index), `_template.md`, and `t1059-001-powershell-encoded.md` populated and at `status: saved-search-active`.
9. [ ] `vault/CLAUDE.md` schema table updated to include the `vault/detections/` row.
10. [ ] `vault/architecture/components/splunk.md` updated with: the new saved search, the Sysmon channel as a recognized data source, the index/sourcetype/source distinction documented for Sysmon events, cross-reference to the new `sysmon.md` component page.
11. [ ] `vault/architecture/components/sysmon.md` exists with: what-it-is paragraph, where-it-runs in the lab, configuration table (config source + commit SHA + version), EventCode reference table, field reference table, the "source= not sourcetype=" gotcha, smoke-test queries, references. Cross-referenced from `splunk.md` and from D1's runbook.
12. [ ] `runbook.md` for D1 covers: Sysmon install, ART install, Universal Forwarder config edit, the "run a technique" loop, snapshot discipline, the **5–7 starter SPL queries** (procedural part of the observation toolkit, annotated inline), security-posture note (Defender off, intentional), the worked example as the smoke-test template, and the standby system-prompt-addendum fix. Reference catalogs (EventCode + field tables) live in `sysmon.md` and are referenced, not duplicated, here.
13. [ ] `notes.md` captures gotchas hit during build (mirroring A1/A2's discipline).
14. [ ] Log entry at vault root marks D1 complete.
15. [ ] If Outcome B occurred during live-fire (gate fired), the runbook's "live-fire validation" section documents it as a known acceptable variance — not a bug to fix.

No ADR is currently planned for D1. (A1 wrote ADR 0004 for MCP mirroring; A2 wrote ADR 0005 for the additive `ioc_type` schema. D1 doesn't introduce a comparable irreversible-or-rationale-heavy decision. If one surfaces during implementation — e.g., we discover we need to install the Splunk Add-on for Microsoft Sysmon and want to record that choice — it becomes ADR 0006.)

## Open questions for the implementation plan (Phase 0 verifies)

These are HOW questions to verify at task-step granularity, not WHAT questions for design:

1. **Universal Forwarder `inputs.conf` path on this Windows 10 VM.** Almost certainly `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`, but verify before editing.
2. **Sysmon sourcetype assignment.** Splunk Add-on for Microsoft Windows handles standard Windows Event Log channels; confirm Sysmon's Operational channel auto-extracts fields. If not, install Splunk Add-on for Microsoft Sysmon.
3. **Exact ART test number for T1059.001.** Test 2 is the working assumption; `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` produces the catalog. Pick the test that runs a Defender-safe encoded command and doesn't require user interaction. (Defender is off, so the constraint relaxes — but interactive-prompt tests still have to be answered.)
4. **Splunk saved-search webhook payload exact schema.** Inspect the actual JSON Splunk POSTs (e.g., capture one webhook delivery in n8n with a temporary debug node, or use `requestbin`-style intermediary). Compare to A1's brute-force-search payload to identify any envelope differences.
5. **Whether `Hashes` field is populated for `powershell.exe` under SwiftOnSecurity.** Affects nothing in D1's worked example, but flagged so the catalog's first observation captures actual behavior.
6. **Claude's behavior on the Sysmon payload.** Outcome A vs. B (per Section 3.6). Phase 0 doesn't pre-test Claude's response; the live-fire is the test.
7. **VMware Workstation snapshot mechanism.** Confirm the user takes/reverts snapshots via the GUI as expected; runbook documents the menu path.
8. **SSH access to the Windows 10 VM for the D1 install set.** Verify OpenSSH Server is running, creds available (likely in `../SOC-Automation-Project.md` at project root, gitignored), the SSH session lands in a context that can run admin PowerShell or escalate. Per user authorization 2026-04-30, install commands D1 calls for are pre-approved to run via SSH; ART invocations and snapshot management remain user-driven. If SSH access fails or admin context isn't available, install steps fall back to the user RDP'ing in and running commands by hand.
9. ~~Saved search earliest/latest window vs. existing brute-force search pattern.~~ **Resolved 2026-04-30:** Time Range and trigger semantics match existing brute-force search — `Time Range: Last 24 hours`, `Trigger: For each result`, `Throttle: unchecked`, `Trigger Actions: Webhook + Add to Triggered Alerts`. **Cron differs intentionally:** D1 uses `*/5 * * * *` (standard SOC cadence) where the brute-force search uses `* * * * *` (a test value). Splunk's "For each result" hash-dedup prevents repeat-firing for result rows the search re-encounters across cron ticks. Phase 0 still observes the live-fire behavior (run ART twice with a 6+ minute gap, confirm two distinct webhooks land) to confirm dedup works for Sysmon-shaped result rows the same way it does for brute-force-shaped result rows.

## What this enables next

Closing D1 unlocks:

- **A3 — Splunk lookup blocklist.** Architectural dependency on A2's gate pattern unchanged. A3 can reference D1's saved-search-creation pattern as a precedent.
- **C — Detection engineering at scale.** Inherits the populated `vault/detections/` directory and the per-technique-page schema as the seed for MITRE coverage map.
- **H — Automated purple team.** Inherits D1's manual run loop as the basis for cron-driven automation.
- **B — EDR layer.** Independent; can extend or replace D1's Sysmon-only telemetry surface with no architectural conflict.
- **The user's stated goal.** "Run any MITRE technique and see how it looks in Splunk." D1 is the foundation that makes this a runbook routine, not a sub-project.

## Predecessors

- **A1 — Structured Outputs** (shipped 2026-04-28). Provides the schema-driven Claude triage that D1's worked-example saved search exercises.
- **A2 — Iris Escalation Gate** (shipped 2026-04-30). Provides the human-in-the-loop gate. D1's worked-example fires the gate-skipped path (matching A2 Test 1) on Sysmon-shaped data.

## Successors

Sequencing as of 2026-04-30 (per [[../../architecture/target-state#sequencing-decision-2026-04-30]]):

- **A3 — Splunk lookup blocklist.** Reuses A2's gate pattern; adds a second action behind it (write IPs to a Splunk KV-store lookup that detection rules query). When A3 introduces a *second* action type, that's the moment to bump A1's schema to v2 with structured `proposed_actions` per [[../../decisions/0005-additive-ioc-type-schema-enhancement]].
- **C — Detection engineering at scale.** Inherits D1's `vault/detections/` directory.
- **H — Automated purple team.** Inherits D1's manual run loop.
- **B — EDR layer.** Independent.

---

## Errata (in-flight corrections during D1 execution)

These corrections were applied during D1 implementation when Phase 0 surfaced realities the spec hadn't anticipated. Captured here per the precedent set by A2's spec.md Errata section.

### E1: Sysmon source filter — `XmlWinEventLog:` not `WinEventLog:`

**Original spec text** (§ 2.4, § 2.5, § 2.10, § 3.3, smoke test queries): `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"`

**Corrected:** `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` — applied via global replace in this file and in `plan.md`.

**Why:** Phase 0 (2026-04-30) discovered that the existing UF `inputs.conf` already had a Sysmon stanza (predating D1 by ~5 days) with an explicit `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` override. During Phase 0 investigation, the user installed the **Splunk Add-on for Microsoft Sysmon** (`Splunk_TA_microsoft_sysmon` v5.0.0, Splunkbase) — that add-on's props/transforms are keyed on the `XmlWinEventLog:` source value. Keeping the override is the canonical pattern when the Sysmon Add-on is installed (the add-on rationalizes the override). The spec's original assumption (default `WinEventLog:` prefix) reflected the world before the Sysmon Add-on existed in this lab.

**Impact:** SPL detection for T1059.001 (§ 2.5), all observation-toolkit queries (§ 2.9), smoke-test queries, and the worked-example walkthrough (§ 3) all use the corrected source string.

### E2: Phase 2 Tasks 2.1 / 2.2 reduce to verify-only

**Original plan:** backup `inputs.conf`, append a new Sysmon stanza, restart forwarder.

**Corrected (in plan.md):** stanza already exists from prior tutorial setup (2026-04-25). D1 only restarts the forwarder; no `inputs.conf` edit happens. Defensive backup retained.

### E3: Forwarder restart activates dormant overrides on PowerShell and Windows Defender stanzas

The pre-existing `inputs.conf` also has `source =` overrides on the `Microsoft-Windows-PowerShell/Operational` and `Microsoft-Windows-Windows Defender/Operational` stanzas — overrides that hadn't taken effect because the forwarder hadn't been restarted since the 2026-04-25 edit. D1's Phase 2 restart activates them as a side effect: those channels' `source` field values in Splunk lose the `WinEventLog:` prefix.

**Vault grep (2026-04-30) confirmed zero downstream consumers** of the old (`WinEventLog:Microsoft-Windows-PowerShell/Operational`, `WinEventLog:Microsoft-Windows-Windows Defender/Operational`) source strings — no breakage. Phase 8's `splunk.md` update notes the change in passing for any future search/dashboard work.

### E4: SPL regex broadened — match `-e`, `-en`, `-enc`, plus full `-EncodedCommand`

**Original spec text** (§ 2.5 SPL clause): `regex CommandLine="(?i)\s-(en?c|encodedcommand)\s"`

**Corrected:** `regex CommandLine="(?i)\s-e[ncodedommand]*\s"` — applied via global replace.

**Why:** Phase 4 ran `Invoke-AtomicTest T1059.001 -TestNumbers 15` (the chosen worked-example test — see E6 below). The actual `CommandLine` Sysmon captured was `powershell.exe -NoProfile -E <base64>` — using PowerShell's bare `-E` form. The original regex required at least `-ec` or `-enc` (the `n?` makes the `n` optional, but the `c` is mandatory) and would have produced **zero hits** against the real test event.

The corrected regex matches `-e` plus any sequence of letters drawn from the alphabet `{n,c,o,d,e,m,a}` (the letters in "ncodedcommand"). This catches all of PowerShell's valid prefix-shortenings (`-e`, `-en`, `-enc`, `-encod`, `-encoded`, `-encodedc`, etc., up to the full `-encodedcommand`) while rejecting false positives like `-eq`, `-ed`, `-ep` because those continue with letters not in the alphabet.

**Trade-off:** the alphabet-based matcher accepts a few non-PowerShell-valid fragments like `-eee` or `-em` if they ever appear in a `powershell.exe` CommandLine — but those are vanishingly rare in practice. If a future false-positive is observed, narrow to a strict prefix-of-`encodedcommand` match: `\s-e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\s`.

### E5: Group-by field rename — `host` not `ComputerName`

**Original spec text** (multiple sections): `by _time, ComputerName, User, Image` and `| table _time, ComputerName, User, Image, ...`

**Corrected:** `by _time, host, User, Image` (and the corresponding `| table` lines) — applied via global replace.

**Why:** the Splunk Add-on for Microsoft Sysmon (installed during Phase 0 — see E1) populates the `host` field with the originating Windows hostname; it does **not** populate `ComputerName`. Verified during Phase 4 SPL development: piping a known event through `| stats by ComputerName` yielded an empty grouping field, while `| stats by host` returned `DESKTOP-VNEF7PC` correctly.

The Sysmon component page (Phase 8 `vault/architecture/components/sysmon.md`) Field Reference table is also updated to mark `host` (not `ComputerName`) as the canonical hostname field for Sysmon events under this Splunk add-on.

### E6: T1059.001 test number — Test 15, not Test 2

**Original spec text** (§ 3.1, § 3.4): "ART Test 2 of T1059.001"; "Test 2 is the working assumption."

**Corrected:** **Test 15** ("ATHPowerShellCommandLineParameter -EncodedCommand parameter variations") — applied during Phase 3's catalog inspection.

**Why:** the spec acknowledged Test 2 as a "working assumption" pending Phase 0 verification. Phase 3 inspected the actual atomics catalog (commit pulled 2026-04-30, 22 tests for T1059.001) and Test 2 turned out to be "Run BloodHound from local disk" — wrong technique. The right test for D1's worked-example is **T1059.001-15** (the `ATHPowerShellCommandLineParameter -EncodedCommand parameter variations` test). The `ATH` prefix marks it as an Atomic Test Harness synthetic — benign payload (decodes to `Write-Host <test-guid>`), no external dependencies, no user prompts, well-defined cleanup.

The worked-example detection page in `vault/detections/t1059-001-powershell-encoded.md` references Test 15 as the canonical D1 worked example.
