---
status: ready
updated: 2026-05-20
related: [[2026-05-19-test-run-handoff]], [[../../detections/t1059-001-powershell-encoded]], [[../../subprojects/2026-04-30-detection-foundations/runbook]]
---

# Demo Video — Full Script, Shot-by-Shot, Recording Setup, Post-Record Artifacts

Visibility-sprint deliverable for the career action plan (parent-workspace `docs/`, outside this repo), Days 2-7. 3-5 min demo of the SOAR pipeline firing end-to-end on the **T1059.003 Suspicious cmd.exe IOC References** detection (validated end-to-end on 2026-05-20).

**Approach:** Hybrid — short live talking-head intro + silent screen capture with caption overlays. Recorded with OBS. Storyline: Linear walk-forward.

**Detection used:** T1059.003 (cmd.exe with embedded IP + SHA256). Naturally exercises **both** enrichment tools (AbuseIPDB on the Tor exit IP, VirusTotal on the EICAR hash), unlike T1059.001 which doesn't have IOCs in its synthetic payload.

---

# Pass 1 — Script & Shot-by-Shot

## Overall structure & timing budget

Target ~3:30 (ceiling 4:00).

| Beat | Mode | Duration |
|---|---|---|
| 0. Talking-head intro | Webcam + live voice | ~25s |
| 1. Endpoint fires technique | Silent screen capture + caption | ~25s |
| 2. Splunk indexes + saved search | Silent screen capture + caption | ~40s |
| 3. n8n execution view | Silent screen capture + caption | ~40s |
| 4. Claude triage output | Silent screen capture + caption | ~40s |
| 5. IRIS alert page | Silent screen capture + caption | ~25s |
| 6. Outro | Webcam + live voice or caption card | ~15s |

## Beat 0 — Talking-head intro (read aloud, ~30s, ~110 words)

> Hi, I'm Armando, a recent graduate from George Mason University. Today I'll be showcasing the lab I built to teach myself detection engineering and SOC automation. The tech stack includes:
>
> - Splunk as the SIEM
> - Sysmon on a Windows VM
> - n8n as the SOAR platform
> - Claude AI as a Tier 1 triage analyst, with VirusTotal and AbuseIPDB as enrichment tools
> - DFIR-IRIS for case management
>
> Throughout the video, you'll see a simulated attack on my Windows VM and watch as it traverses n8n, the SOAR platform, and lands as a case in IRIS. Let's begin.

Casual delivery preferred. Bullet items give natural beat-breaks while reading aloud. Load-bearing terms: *detection engineering, SOC automation, Tier 1 triage analyst, simulated attack, lands as a case in IRIS*.

## Beat 1 — Endpoint fires the technique (~25s)

**On screen:** Win10-v2 RDP/console session. Admin PowerShell. Run the cmd.exe IOC-laden synthetic:

```powershell
$guid = [guid]::NewGuid().ToString()
"Firing T1059.003 IOC demo at $(Get-Date -Format 'HH:mm:ss')"
cmd.exe /c "echo demo-$guid && echo IOC_IP=185.220.101.42 && echo IOC_HASH=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f && exit"
```

**Caption overlays:**
- *"Simulated attacker tradecraft: cmd.exe with embedded IOCs."*
- *"IP literal = Tor exit relay. SHA-256 = EICAR test file."*
- *"Sysmon captures the process-create event."*

## Beat 2 — Splunk indexes + saved search fires (~40s)

**On screen:** Splunk web at `192.168.129.131:8000`.

1. Paste SPL ad-hoc + run (time picker: Last 5 minutes):
   ```spl
   index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
   EventCode=1 Image="*\\cmd.exe" CommandLine="*/c*"
   | regex CommandLine="(?i)((?:\b\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{64}\b|http://|https://)"
   ```
2. Show result row — expand, cursor at `Image`, `CommandLine` (with IOC strings), `ParentImage` (powershell.exe).
3. Navigate: **Settings → Searches, reports, and alerts → `T1059.003 - Suspicious cmd.exe IOC References`**. Show cron `*/5 * * * *` + webhook trigger action.

**Caption overlays:**
- *"Universal Forwarder ships the event to Splunk in seconds."*
- *"Saved search regex matches the IOC patterns (IP, SHA-256)."*
- *"On match: webhook trigger fires into n8n."*

## Beat 3 — n8n execution view (~40s)

**On screen:** n8n web at `192.168.129.132:5678`.

1. Click **Executions** in left nav. Click into the new green execution.
2. Canvas shows nodes in order: `Webhook` → `Message a model (Claude)` → tools (`AbuseIPDB`, `VirusTotal`, `submit_triage_result`) → `Extract Triage Result` → `Create Iris Alert`.
3. All nodes show green checkmarks. Tools panel shows item counts (e.g., AbuseIPDB ✓1, VirusTotal ✓1).

> ⚠️ Recording-time: Do NOT click into any node's Credentials field. Stay on the canvas and the per-node output panels.

**Caption overlays:**
- *"n8n receives the webhook; hands the alert to Claude with three tools."*
- *"Tools: AbuseIPDB (IP rep), VirusTotal (hash rep), structured-output submission."*

## Beat 4 — Claude triage output (~40s)

**On screen:** Same n8n execution view. Click each tool node to show output, then `Message a model` for the synthesis.

1. **enrich_ip_abuseipdb output** — JSON with abuse-confidence score, ISP, country (Tor exit relay data)
2. **lookup_file_hash_virustotal output** — JSON with detection ratio (~65/67 for EICAR)
3. **Message a model output** — Claude's structured triage citing both enrichments in prose

**Caption overlays:**
- *"AbuseIPDB returns 100% confidence — known Tor exit relay."*
- *"VirusTotal flags the hash as EICAR (test file)."*
- *"Claude synthesizes severity, MITRE mapping, and prose triage."*

## Beat 5 — IRIS alert page (~25s)

**On screen:** IRIS at `https://192.168.129.133/alerts`. Click through self-signed cert.

1. New alert at top — click into it.
2. Show title (`T1059.003 - SUSPICIOUS CMD.EXE IOC REFERENCES`), severity, prose summary referencing both IOCs and their enrichment, MITRE techniques (T1059.003, T1059.001).

**Caption overlays:**
- *"Alert lands in DFIR-Iris as a case-management ticket."*
- *"Severity, MITRE mapping, and enriched intelligence — ready for analyst review."*
- *"Human-in-the-loop: AI does the triage, human owns the decision."*

## Beat 6 — Outro (~18-20s, ~55 words)

> And that's the full chain from the Windows VM to IRIS case management, fully automated. GitHub repo and architecture docs are linked in the description below. Now, what I plan to do next is move this on to Microsoft Sentinel and Azure in an effort to learn those Microsoft systems. Thanks for watching.

Casual delivery preferred, matching the Beat 0 intro tone. Honest framing on the Azure work as "in an effort to learn" rather than overclaiming readiness.

Caption card alternative (if you'd rather skip the second talking-head clip): *"End-to-end: Sysmon → Splunk → n8n → Claude → IRIS"* / *"Repo + 7 ADRs + runbooks linked below."* / *"Microsoft Sentinel + Azure version up next."*

---

# Pass 2 — Recording Setup

## OBS scene configuration

Two scenes, both pre-built:

### Scene 1 — "Talking head"
- **Video Capture Device:** webcam, sized to full canvas (1920x1080)
- **Audio Input Capture:** your mic
- Use for: Beat 0 (intro) and optionally Beat 6 (outro)

### Scene 2 — "Screen capture"
- **Display Capture:** primary monitor (the one where Splunk/n8n/IRIS will be open)
- No webcam overlay (cleaner read; webcam corner often distracts from technical content)
- **Audio Input Capture:** mic still active in case you want to drop in voiceover mid-demo
- Use for: Beats 1-5

### OBS encoder settings (Settings → Output → Recording)
- **Recording Format:** MP4
- **Encoder:** x264 (software) — most compatible
- **Rate Control:** CRF, value `22` (a good quality/size balance for screen capture)
- **Preset:** `veryfast` (faster encode, fine for screen capture)
- **Keyframe Interval:** 2 sec
- **Resolution:** 1920x1080
- **FPS:** 30

### Audio settings (Settings → Audio)
- **Sample Rate:** 48 kHz
- **Audio Bitrate (in Output → Audio Track):** 160-192 kbps AAC
- **Mono mic, stereo output** — most desktop mics are mono; OBS will duplicate to stereo

## Mic guidance

- **Built-in laptop mic** — workable for a first take. Get close to the laptop (~30 cm). Test before recording (record 10 sec, play back, check for hiss/clipping).
- **Recommended upgrade** (any of these is a meaningful step up, <$60):
  - **Fifine K669** (~$30) — USB plug-and-play, surprisingly good for the price
  - **Samson Q2U** (~$60) — USB + XLR, supports growth into better recording
  - **Blue Snowball iCE** (~$50) — USB, popular, good for spoken word
- **Room treatment:** soft surfaces reduce echo. A cloth/towel draped over a hard table behind you helps. Hard rooms (tile, glass, bare walls) produce harsh recordings.
- **OBS audio meter levels:** during your test, speak normally. The meter should peak at **-12 to -6 dB** (yellow zone). If it's hitting red (clipping) or staying under -24 dB (too quiet), adjust the mic input gain in Windows Sound settings or in OBS's mixer.

## Editor recommendation — for adding caption overlays

Pick ONE based on your comfort level:

1. **Clipchamp (Windows 11 built-in)** ⭐ recommended for first take
   - Free, already installed on Win11
   - Drag-and-drop interface
   - Title cards / text overlays are 2-click adds
   - Export to MP4 is one button
   - Limitation: 1080p export requires Microsoft account sign-in (free)

2. **CapCut** — free, good auto-captions if you'd rather speak the captions and have them auto-generated. Slightly more complex than Clipchamp.

3. **DaVinci Resolve** (free version) — powerful but steep learning curve. Overkill for a 3-min demo.

**Don't:** try to add captions in OBS at record-time. Cleaner to add in post.

## Hosting platform — YouTube unlisted (recommended)

**Why YouTube unlisted over Loom:**
- ✅ Free, permanent URL
- ✅ Embeddable in GitHub README and LinkedIn Featured
- ✅ "Unlisted" = anyone with the link can view; not searchable; doesn't show in your channel's public videos
- ✅ Easy to make public later if you want
- ✅ YouTube transcribes captions for you (auto-generated from voice + embeds your overlay captions if burned in)
- ❌ Loom is better for one-take live narration, not hybrid + edits

**Upload settings:**
- Title: `SOC Automation Pipeline — End-to-End SOAR Demo (Splunk + n8n + Claude + IRIS)`
- Description (use the LinkedIn template below as a starting point + add timestamps for each beat)
- Visibility: **Unlisted**
- Made for kids: **No** (this matters; sets it as "adult-targeted" content with full features)
- Tags: `cybersecurity, detection engineering, SOAR, Splunk, n8n, Claude API, MITRE ATT&CK, SOC`

## Recording-day checklist (do this 5-10 min before hitting record)

- [ ] Reboot Win10-v2 (clean state, no leftover PowerShell or browser windows; Sysmon should auto-start)
- [ ] Confirm Splunk web UI loads (`http://192.168.129.131:8000`)
- [ ] Confirm n8n web UI loads (`http://192.168.129.132:5678`) and workflow Active toggle is GREEN
- [ ] Confirm IRIS web UI loads (`https://192.168.129.133/alerts`)
- [ ] Sanity SPL: `index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-5m | stats count` returns > 0
- [ ] In IRIS, note the current top alert ID (so you can confirm "yes, the new one is the alert that just fired")
- [ ] OBS test recording: 10 seconds of Scene 1, play back, check audio levels and webcam framing
- [ ] Browser tabs pre-loaded so you don't have to navigate during recording:
  - Tab 1: Splunk search page
  - Tab 2: Splunk Settings → Searches, Reports, and Alerts (filtered to your T1059.003 alert)
  - Tab 3: n8n Executions
  - Tab 4: IRIS /alerts
- [ ] Win10-v2 RDP/console window open with admin PowerShell prompt ready
- [ ] Close noisy programs (Discord, Slack, Spotify, etc.)
- [ ] Phone on silent
- [ ] Take a deep breath. First take goal: workable, not perfect.

## Cron-tick timing trick

Splunk's saved search runs on `*/5 * * * *` UTC boundaries (`:00 :05 :10 :15 :20 :25 :30 :35 :40 :45 :50 :55` UTC). To minimize on-screen waiting:

**Fire the cmd.exe synthetic ~30-60 seconds BEFORE a 5-min UTC boundary.** That way, between firing and showing the n8n + IRIS results, the cron will tick and the pipeline will run during the natural beat transition.

Convert UTC to local time mentally as needed (EDT = UTC - 4).

## Recording flow (the actual take)

1. **Hit Record** in OBS. Switch to Scene 1.
2. Read intro (~25s).
3. Switch to Scene 2.
4. Win10-v2 PowerShell → fire the cmd.exe synthetic (~5s).
5. Switch to Splunk tab → SPL ad-hoc → show event → switch to saved-search settings → quick walkthrough (~40s).
6. Switch to n8n → Executions → click newest → walk through nodes (~40s).
7. Click into Claude's tool calls → show AbuseIPDB + VT outputs → show Claude's synthesis (~40s).
8. Switch to IRIS → /alerts → click newest → show the populated triage (~25s).
9. Optional: switch back to Scene 1 → read outro (~15s). Or insert a caption card in post.
10. **Stop Recording.**

## Post-record processing

1. **Trim** opening and closing dead air in your editor.
2. **Add caption overlays** at each beat boundary (use the exact text from this script's caption sections).
3. **Optionally:** add a soft background music track at low volume (-30 to -25 dB). Free royalty-free music from YouTube Audio Library. Skip for first take if unsure.
4. **Export** at 1080p MP4, h.264, AAC audio.
5. **Upload** to YouTube unlisted with the title/description/tags above.

---

# Pass 3 — Post-Recording Artifacts

## README embed pattern

GitHub README markdown doesn't natively embed YouTube players. Use a thumbnail-linked-to-video pattern:

```markdown
## Demo

[![Watch the ~3 min demo](https://img.youtube.com/vi/VIDEO_ID/maxresdefault.jpg)](https://youtu.be/VIDEO_ID)

~3 minute walkthrough of the SOAR pipeline firing end-to-end on a T1059.003 detection.
Watch the full pipeline: endpoint event → Splunk → n8n → Claude triage with AbuseIPDB + VirusTotal enrichment → DFIR-Iris case.
```

Replace `VIDEO_ID` with your actual YouTube video ID (the 11-character string after `?v=` in the YouTube URL).

**Placement:** add to your README **just after the architecture diagram, before "What's in the repo"**. The video should be one of the first things a visitor sees — recruiters skim repos but watch short demo videos.

## LinkedIn Featured post draft

This is what you announce the video with. Edit to taste, but keep the structure: lead with the artifact, link the repo, end with the open-to-work signal.

```
I built an end-to-end SOAR pipeline as a portfolio project:
Splunk SIEM → n8n SOAR → Claude API for Tier-1 triage → DFIR-Iris for case management.

This ~3 min walkthrough shows it firing on a T1059.003 detection (suspicious cmd.exe with embedded IOCs):

• Sysmon catches the process-create event on the Windows endpoint
• Splunk saved search regex-matches the IOC pattern (IP, SHA-256)
• Webhook fires to n8n; Claude triages with three tools available
• Claude calls AbuseIPDB (Tor exit, 100% confidence) and VirusTotal (EICAR hash flagged)
• Returns structured triage; alert lands in DFIR-Iris with severity, MITRE mapping, and prose summary

Repo (architecture, 7 ADRs, runbooks, full decision history): https://github.com/Armando-ic/SOC-Automation-Project

I'm a fresh GMU cybersecurity grad (May 2026) based in Northern Virginia — US citizen, clearance-eligible, open to entry-level detection engineering / SOAR / SOC analyst roles. Building a Microsoft Sentinel + Azure parallel implementation next.

Open to chat — DMs are open.

#cybersecurity #detectionengineering #SOAR #splunk #n8n #SOC #newgrad #ClaudeAPI #MITREATTACK
```

### How to set up the Featured section on LinkedIn

1. Go to your LinkedIn profile
2. Scroll to **Featured** section (under About). If you don't see one, scroll to the bottom of About and click "Add profile section" → "Featured"
3. Click the `+` → **Add a link**
4. Paste the YouTube unlisted URL
5. LinkedIn fetches the title and thumbnail; you can edit the title/description as displayed
6. Save

The repo can be added the same way as a second Featured link.

### Posting strategy

Don't just add to Featured silently. **Post about it** so it shows up in your activity feed and your network sees it:

1. From your LinkedIn home, click "Start a post"
2. Paste the LinkedIn post draft above
3. **Don't paste the YouTube URL into the post text** — instead, attach the video via LinkedIn's "Add video" button (uploads natively to LinkedIn) OR paste the URL and let it auto-preview
4. Post

Repost / re-share monthly during your active job-search window. Different recruiters check at different times.

---

# Open items (post-recording polish, not blocking)

These came up during the 2026-05-19/20 test-run prep. Captured here so they don't get lost. None block the recording.

1. **Enriched IOCs field in IRIS reads `_none_`** despite Claude citing both IOCs in the prose summary. Workflow wiring: the structured `iocs[]` field isn't being populated even though Claude has the enrichment data. Debug the Extract Triage Result Code node + Create Iris Alert payload mapping. See [[2026-05-19-test-run-handoff]] for context.

2. **Update the runbook** (vault/subprojects/2026-04-30-detection-foundations/runbook.md and detection pages) with:
   - Corrected suppress-key recipe: `_time,host,Image` (not `_time,host,Image,CommandLine` — CommandLine doesn't exist post-stats)
   - The Trigger="For each result" requirement for field-based suppress to work
   - n8n credential rotation must be explicit per service (Anthropic + AbuseIPDB + VT + IRIS API)
   - VT account behavior: deactivation can happen silently; key-works-via-curl-but-fails-in-n8n is a credential-wiring issue, not auth

3. **Create vault detection page** for [[../../detections/t1059-003-cmd-suspicious-ioc-references]] (sibling to t1059-001-powershell-encoded.md) once the polish items above land.

4. **Re-enable the T1059.001 saved search** as part of detection-catalog cleanup. Currently disabled to avoid duplicate-alert noise during demo prep. After recording, re-enable with proper throttle config (For each result + `_time,host,Image` suppress key).

5. **Decide whether to install ATH on Win10-v2** (TLS 1.2 fix + Install-Module AtomicTestHarnesses) for future detection work. Optional; the synthetic substitute pattern works for any technique.
