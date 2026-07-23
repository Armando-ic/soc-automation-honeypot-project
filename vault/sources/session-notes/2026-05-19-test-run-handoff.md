---
status: paused
updated: 2026-05-19
related: [[2026-05-19-demo-video-script]], [[../../detections/t1059-001-powershell-encoded]], [[../../subprojects/2026-04-30-detection-foundations/runbook]]
---

# Demo Recording Prep — Test Run Session Notes

Pause point for the 2026-05-19 evening session. Resume from here. Goal: validate the full SOAR chain fires end-to-end before recording the demo video, then proceed to recording.

## Where we are right now (state of the world)

**Test fires today produced these IRIS alerts:**
- Most recent good alert: **#60 — TEST-BRUTE-FORCE-EXTERNAL** (from a pinned-data manual execution; shows what end-to-end success looks like with full AbuseIPDB enrichment)
- Most recent failed cmd.exe execution: **#43** (2026-05-19 20:25 EDT) — failed at VT tool call with "User is inactive"

**What's confirmed working:**
- Splunk indexing (Sysmon events lag ~5s)
- Forwarder + Sysmon emit cleanly post-VM-restart
- Splunk saved-search dispatching on `*/5 * * * *` cron
- New saved search: `T1059.003 - Suspicious cmd.exe IOC References` (SPL fires cleanly on synthetic)
- Webhook → n8n delivery
- Anthropic / Claude credential (fresh key from 2026-05-19 rotation, now working)
- AbuseIPDB enrichment tool (3 successful calls per execution today)
- submit_triage_result tool
- Extract Triage Result + Create Iris Alert nodes
- End-to-end pipeline produces high-quality Claude triage with MITRE mapping + populated IOCs

**What's broken:**
- **VirusTotal tool — `Authorization failed: User is inactive`**
  - Tested with 3 different VT accounts today (last one: `owner@example.com` account 3)
  - All three returned identical error from VT API
  - Confirmed at the failed tool node's Output panel: VT's API endpoint (`/api/v3/files/<hash>`) returns "User is inactive" as the error
  - **Strongly suspected root cause:** VT account email verification not completed, OR VT flagged the account due to rapid account creation (3 accounts in one day from same user)

## Configuration changes made today that need to STAY

### 1. New saved search created — KEEP

**Name:** `T1059.003 - Suspicious cmd.exe IOC References`

**SPL:**
```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\cmd.exe" CommandLine="*/c*"
| regex CommandLine="(?i)((?:\b\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{64}\b|http://|https://)"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image
```

**Config:**
- Schedule type: Run on Cron Schedule (NOT Real-Time — runbook gotcha)
- Cron: `*/5 * * * *`
- Time Range: Last 24 hours
- Trigger: **For each result** (NOT "Once" — produces Digest mode if Once)
- Throttle: ✅ checked
- Suppress results containing field value: `_time,host,Image`
- Suppress period: 86400 seconds
- Trigger Actions: Add to Triggered Alerts + Webhook to `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd`

### 2. Existing T1059.001 saved search DISABLED — KEEP DISABLED for now

Re-enable later as part of detection catalog cleanup. Currently disabled to prevent noise during recording prep.

### 3. n8n credential updates today

All three credentials in n8n's Credentials section were updated today:
- Anthropic API key (rotated 2026-05-18, n8n credential updated 2026-05-19)
- AbuseIPDB API key (rotated 2026-05-18, n8n credential confirmed working — 3 successful calls per execution)
- VirusTotal API key (rotated to `owner@example.com` account 3 — STILL FAILING)

## VirusTotal diagnosis plan for next session

Run these in order. Stop when symptoms clear.

### Step 1 — Verify the VT account email (fastest fix, ~2 min)
- Log into `owner@example.com`
- Check inbox + spam + Promotions tab for an email from `noreply@virustotal.com` (subject likely "Welcome to VirusTotal" or "Please verify your email")
- If found, click the verification link
- Try fresh fire afterward

### Step 2 — Test the VT API key directly via curl (bypasses n8n entirely)
From any machine with internet access:

```bash
# Replace <KEY> with the VT API key from SOC-Automation-Project.md (don't echo it)
curl -s -H "x-apikey: <KEY>" \
  "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" \
  | head -20
```

Expected (working): JSON with `data.attributes.last_analysis_stats` etc.
Expected (broken): JSON with `error.code: UserNotActiveError` or similar.

**If curl reproduces "User is inactive"** → the key/account itself is the problem; verify email or regenerate key from the VT dashboard.

**If curl works fine** → the n8n credential is misconfigured (wrong header name, wrong auth method, etc.). Re-check the n8n VT credential's auth type.

### Step 3 — Inspect VT account dashboard
Log into VT web UI (`owner@example.com` account 3) → check:
- "API key" page — is the key listed? Is there a state/status indicator?
- Account settings — any "verify email" banner at the top?
- Privileges — free-tier accounts have rate limits (4 req/min, 500/day); check current quota

### Step 4 — Regenerate the VT API key (sometimes fixes inactive-key state)
On the VT API key page, there's usually a "Regenerate" option. Generate fresh key, update n8n credential, retry.

### Step 5 — If still broken, accept and ship without VT
Disable the VT tool node in the n8n workflow (right-click → Deactivate). Workflow then runs with two tools: AbuseIPDB + submit_triage_result. Demo framing: *"VT integration is wired in but offline during my credential rotation this week — AbuseIPDB is the active enrichment for today."* Honest, recruiter-defensible.

## What's still queued for the recording deliverables

Original task from primary Claude session: 4 deliverables.

1. **Video script + shot-by-shot** — ✅ DONE, saved to [[2026-05-19-demo-video-script]]
2. **Recording setup (OBS scenes, mic, editor, YouTube unlisted)** — ⏸ NOT STARTED. Pass 2 of the script doc. Pick up after VT diagnosis is resolved.
3. **README embed pattern** — ⏸ NOT STARTED. Pass 2 work.
4. **LinkedIn Featured post draft** — ⏸ NOT STARTED. Post-recording work.

## Open questions / decisions for next session

- ATH install on Win10-v2? (TLS 1.2 fix + Install-Module AtomicTestHarnesses). Or stick with synthetic for the recording? Synthetic was the runbook fallback and works fine; ATH gives more authentic ParentImage (`WmiPrvSE.exe`) but adds 60s of setup work.
- Should the demo use the cmd.exe T1059.003 path (just built tonight) or the original T1059.001 PowerShell encoded-command path (the one in the vault detection page)? The cmd.exe one exercises AbuseIPDB + VT enrichment naturally because IOC strings are embedded; the PS-encoded one is the documented worked example with full vault narrative. **Recommendation: record on the new T1059.003 path** — it's the one with verified working IOC enrichment, plus it gives you a second documented detection to reference in the recording.

## Documentation follow-ups (post-recording)

Items learned today that should be backfilled into the runbook + detection pages:

1. **Splunk saved-search throttle gotchas:**
   - The "Suppress results containing field value" textbox only appears when **Trigger = For each result** (not "Once")
   - "Once" mode = Digest mode = ONE alert per dispatch, suppressed globally for the entire saved search
   - The runbook's suppress-key recipe `_time,host,Image,CommandLine` is broken because `CommandLine` doesn't exist in the SPL's `stats` output (it's renamed to `command_lines`). **Correct recipe:** `_time,host,Image` (sufficient because `_time` is per-event unique)
2. **n8n credential rotation steps must be explicit:** the 2026-05-18 secrets-management runbook says "update n8n credentials" but doesn't enumerate which credentials. Today proved that step is critical AND easy to skip — Claude/Anthropic credential update was missed during the original 2026-05-18 rotation.
3. **VT free-tier multi-account behavior:** create-multiple-accounts-rapidly may trigger an inactive-account flag. Worth documenting.
4. **New T1059.003 detection should get its own vault page** under `detections/` once validated end-to-end. Sibling to t1059-001-powershell-encoded.md.

## Session-end todo state

In-flight (will reset on next session):
- Phase 5 green-light decision pending VT resolution

Completed today:
- Phase 1 pre-flight ✅
- Phase 2 baseline capture ✅
- Phase 3 fire technique ✅
- Phase 4 all stages ✅ (with VT caveat)
- Created new T1059.003 saved search ✅
- Fixed credential rotations (Claude + AbuseIPDB) ✅
- Fixed Splunk saved-search throttle config (For each result + per-row suppress key) ✅
- Identified mystery 22:39 event source (user's own earlier atomic test) ✅

Still pending:
- VT working OR accepted-and-disabled
- Recording setup recommendation (Pass 2 of script doc)
- README embed pattern
- LinkedIn Featured post draft
- Actually recording the demo
