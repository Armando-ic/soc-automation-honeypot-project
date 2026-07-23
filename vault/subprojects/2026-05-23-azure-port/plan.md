---
status: complete
updated: 2026-05-26
sub_project: P2 (Azure Port)
related: [[README]], [[spec]], [[runbook]], [[notes]]
---

# P2 — Azure Port (v1 → Azure IaaS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port v1's Splunk + n8n + DFIR-IRIS from local VMware to Azure IaaS, verify end-to-end pipeline parity, then decommission the 4 local VMs (3 Linux + Win10 endpoint) to recover C: drive space.

**Architecture:** Three new Azure Linux VMs (`vm-soc-v2-splunk`, `vm-soc-v2-n8n`, `vm-soc-v2-iris`) provisioned into Phase 1's existing Central US resource group + VNet. Splunk fresh-installs (new 60-day trial clock; Dev License application in parallel). n8n + IRIS redeploy via docker-compose with state imported (workflow JSON for n8n from git; pg_dump/restore for IRIS Postgres). Phase 1's `vm-soc-v2-win` Sysmon UF re-pointed at new Splunk in parallel to its existing AMA → Log Analytics output. Source-IP-restricted public IPs on all 3 VMs; intra-VNet private IPs for the alert pipeline.

**Tech Stack:** Azure Portal (no az CLI), Ubuntu Server 24.04 LTS, Splunk Enterprise 10.2.2, n8n via docker-compose, DFIR-IRIS 2.4.22 via docker-compose, PostgreSQL.

---

## File structure

| Path | Status | Responsibility |
|---|---|---|
| `SOC-Automation-Project-to-Azure-Port.md` | CREATE (Task 4) | Cherry-picked from `v3-microsoft-native` so the handoff doc is discoverable from `v2-azure` working tree |
| `vault/subprojects/2026-05-23-azure-port/notes.md` | CREATE (Task 3) | Working notes — Phase 1 RG/VNet/subnet discovery, home IP, license-app status, gotchas |
| `vault/subprojects/2026-05-23-azure-port/runbook.md` | CREATE (Task 25) | Operational runbook — how to operate the migrated stack, troubleshooting, daily-ops checklist |
| `vault/subprojects/2026-05-23-azure-port/comparison-latency.md` | CREATE (Task 24) | Side-by-side latency comparison v1 (local VMware) vs P2 (Azure IaaS); seed table for future Phase 3 numbers |
| `vault/architecture/components/splunk.md` | MODIFY (Task 26) | Add Azure section: new IP, new size, new install version baseline, MCP reconfiguration note |
| `vault/architecture/components/n8n.md` | MODIFY (Task 26) | Same: new IP, docker-compose path, credential recreation log |
| `vault/architecture/components/dfir-iris.md` | MODIFY (Task 26) | Same: new IP, Postgres version pin used, restore method captured |
| `vault/architecture/current-state.md` | MODIFY (Task 26) | Update Mermaid diagram: VMware nodes replaced by Azure VM nodes |
| `vault/log.md` | MODIFY (multiple tasks) | Append-only journal entries for each major milestone |
| `vault/subprojects/2026-05-23-azure-port/README.md` | MODIFY (Tasks 24, 25) | Status updates: draft → active (post-Task 6) → complete (post-Task 24) |
| `vault/subprojects/2026-05-23-azure-port/spec.md` | MODIFY (Task 24) | Frontmatter `status: draft → active` once provisioning starts (Task 6); `→ complete` after Task 24 |

**Why no separate `azure/` directory:** The migrated stack lives under existing component docs (`vault/architecture/components/`); the only Azure-specific artifacts are the sub-project's own notes/runbook. Folders named after temporal phases age poorly (per the `v3-microsoft-native` plan's own observation about `phase-2/` vs `logic-app/`); components age well.

---

## Testing approach (read before starting)

Infrastructure provisioning doesn't fit classical TDD. There is no failing-test-then-passing-test cycle for Azure portal clicks or SSH-based install scripts. Instead, each task has explicit **verification steps** that confirm the cumulative state is correct — "build a bit, verify, build a bit more." This is the same discipline applied to the v3-microsoft-native (Phase 3) plan.

**Verification primitives:**
- **Portal observation:** "Resource appears in Status: Provisioned" or "Inbound rule visible in NSG rules table."
- **Shell command on the VM:** SSH in, run a tool, check output. E.g., `splunk version` returns `Splunk 10.2.2`.
- **Network test:** From one VM, attempt to reach another's service port (`curl`, `nc -zv`, etc.).
- **End-to-end pipeline test:** Fire Atomic Red Team T1059.001 Test 15 from `vm-soc-v2-win`, trace the alert through the pipeline.

**Commit cadence:** Portal-only tasks don't produce committable files; verification happens by observation, not by git diff. File-producing tasks (3, 4, 24, 25, 26) get individual commits. The latency comparison + runbook + component-doc updates are bundled into the final two file-producing tasks.

**Rollback per task:** Each task notes its rollback path inline. The default rule: if a verification step fails, do not proceed to the next task. Diagnose, fix, re-verify. The local VM stack remains operational throughout — no source-of-truth state is destroyed until the explicit decommission tasks (20-23) run.

---

## Pre-flight (Tasks 1-5)

### Task 1: Apply for Splunk Developer License (background task)

**Files:** none in this task; license-application-submitted timestamp recorded in Task 3's notes.md.

**Why first:** Approval lead time is typically 3-7 business days. Submitting now means the dev license may arrive before this plan's Splunk install reaches the natural 60-day trial expiry, giving the long-term-stable license target.

- [ ] **Step 1: Navigate to Splunk dev portal**

Open https://dev.splunk.com/enterprise/ in a browser. If you don't have a Splunk.com account, create one (free).

- [ ] **Step 2: Apply for the Developer License**

Click "Get the Developer License" (or current equivalent — UI label may vary). Fill out the application form:
- Use case: "Personal portfolio SOC automation lab — Splunk SIEM in Azure IaaS with Sysmon ingestion, KQL-equivalent saved-search detections, webhook to n8n SOAR, DFIR-IRIS case management."
- Organization: personal / N/A (use your name).
- Intended use: lab / portfolio, not production.

Submit. Note the submission date.

Expected: Confirmation page or email acknowledging the application.

- [ ] **Step 3: Set a reminder for 7-day follow-up**

Calendar / reminder app: 7 business days from today. Topic: "Check Splunk Dev License application status; if not received, follow up at dev.splunk.com."

- [ ] **Step 4: Note submission in vault notes**

This step is deferred to Task 3 (notes.md creation) — the notes file doesn't exist yet. When you create it in Task 3, include the submission date and reminder schedule.

---

### Task 2: vCPU quota pre-flight check

**Files:** none in this task; quota findings recorded in Task 3's notes.md.

**Why:** Phase 1 was forced from East US to Central US by a quota wall. Three more VMs add +8 vCPUs (`D4s_v3` × 1 for Splunk + `D2s_v3` × 2 for n8n/IRIS). If Central US's `Standard DSv3 Family vCPUs` quota doesn't accommodate, file an increase request now.

- [ ] **Step 1: Open Subscription quota view**

Portal → search "Subscriptions" → select your trial subscription → "Usage + quotas" in the left menu.

- [ ] **Step 2: Filter for Central US DSv3 family**

In the filter bar:
- Provider: Compute
- Location: Central US
- Quota type: vCPU
- Search: `Standard DSv3 Family`

Expected: A row labeled "Standard DSv3 Family vCPUs" with `Current Usage / Limit` values. Phase 1's `vm-soc-v2-win` if it's on a DSv3 size will already show in Current Usage; check the limit.

- [ ] **Step 3: Verify ≥ 12 vCPUs available**

Math: Phase 1 uses 4 (D4as_v7 per handoff doc — note this is *not* DSv3 but a different family; if it's not counted in DSv3 quota, only +8 vCPUs needed). New VMs need +8 in DSv3 family (4 for Splunk + 2 each for n8n/IRIS).

If quota limit minus current usage ≥ 8, you're clear. Proceed to Step 5.

If quota limit minus current usage < 8, proceed to Step 4 to file an increase.

- [ ] **Step 4: Request quota increase (if needed)**

Click the pencil/edit icon on the DSv3 row → "Request quota increase." Fill the form:
- Reason: "Portfolio SOC automation lab; deploying 3 additional Linux VMs (1× D4s_v3, 2× D2s_v3) in Central US. Total request: 12 vCPUs."
- Submit.

Expected: Most Trial-tier quota requests for modest amounts are auto-approved within minutes; some require manual review (24-48h).

- [ ] **Step 5: Record current quota and target**

Note the limit + current usage + delta. Will be captured in Task 3 (notes.md). Move on.

---

### Task 3: Create sub-project notes.md and capture Phase 1 resource discovery

**Files:**
- Create: `vault/subprojects/2026-05-23-azure-port/notes.md`

- [ ] **Step 1: Open Phase 1's resource group in the portal**

Portal → search "Resource groups" → find the one in Central US containing `vm-soc-v2-win` and `law-soc-v2-azure`. (Likely `rg-soc-v2-azure-central-us` but verify — handoff doc only names the abandoned East US RG.)

Click into the RG.

- [ ] **Step 2: Catalog the resources you need to know about**

Inside the RG, identify and record:
- **Resource group name** (exact, copy-paste).
- **VNet name** (look for a resource of type "Virtual network"). Click in to see its address space.
- **Subnet name + CIDR** (VNet blade → Subnets).
- **`vm-soc-v2-win` private IP** (VM blade → Networking → primary NIC → IP configurations).
- **`vm-soc-v2-win` size + OS** (VM Overview).
- **Log Analytics workspace name** (`law-soc-v2-azure` per handoff).
- **Any existing NSG name + which subnet/NIC it's attached to.**

- [ ] **Step 3: Source your home IP**

In a browser: visit https://api.ipify.org or https://whatismyip.com.
Note: your home IP. NSG rules will hard-code this. If your IP changes (rotates, you move, you VPN), you'll need to update rules — that's a known risk per spec §6.

- [ ] **Step 4: Create notes.md with the captured findings**

Write `vault/subprojects/2026-05-23-azure-port/notes.md`:

```markdown
---
status: active
updated: 2026-05-23
sub_project: P2 (Azure Port)
related: [[spec]], [[README]]
---

# P2 — Working notes

Append entries as work progresses. Newest at the top.

## Phase 1 resource discovery (Task 3)

| Resource | Name / Value | Notes |
|---|---|---|
| Resource group | `<rg-name-from-portal>` | Central US |
| VNet | `<vnet-name>` | Address space: `<CIDR>` |
| Subnet | `<subnet-name>` | CIDR: `<CIDR>` |
| Existing NSG | `<nsg-name>` (or "per-NIC, no subnet NSG") | Attached to: `<subnet|NIC>` |
| `vm-soc-v2-win` | Private IP: `<10.x.x.x>` | Size: `Standard_D4as_v7`, OS: Windows Server |
| Log Analytics workspace | `law-soc-v2-azure` | Phase 1 workspace; not touched by P2 |
| Home IP for NSG rules | `<your.public.ip>` | Source-IP-restricted access |

## vCPU quota status (Task 2)

| Family | Region | Limit | Current usage | Available | Need +8? |
|---|---|---|---|---|---|
| Standard DSv3 Family vCPUs | Central US | `<limit>` | `<usage>` | `<delta>` | yes / requested / approved |

## Splunk Dev License application (Task 1)

Submitted `<date>`. Follow-up reminder set for `<date+7 business days>`. Status: `pending`.
```

Fill in the actual values from Steps 2 and 3.

- [ ] **Step 5: Commit notes.md**

```bash
git add vault/subprojects/2026-05-23-azure-port/notes.md
git commit -m "docs(v2-azure): add P2 working notes with Phase 1 resource discovery"
```

---

### Task 4: Cherry-pick the handoff doc onto v2-azure

**Files:**
- Create: `SOC-Automation-Project-to-Azure-Port.md` (cherry-pick result)

**Why:** The handoff doc was committed to the old `v2-azure` branch (now `v3-microsoft-native`). The new `v2-azure` branched from `main`, which doesn't have it. Cherry-picking the file's introduction commit makes it discoverable in the active branch's working tree.

- [ ] **Step 1: Find the commit that introduced the handoff doc**

Run: `git log origin/v3-microsoft-native --oneline --diff-filter=A -- SOC-Automation-Project-to-Azure-Port.md`
Expected: One commit hash (likely `acedd79` — the pivot commit per handoff doc's own §"Recent v2-azure branch commit log").

- [ ] **Step 2: Cherry-pick that commit**

Run: `git cherry-pick <commit-sha>` (using the hash from Step 1).

Expected: Cherry-pick succeeds with no conflicts. The commit message is preserved; `git log -1` shows the cherry-picked commit on `v2-azure`.

**If conflicts arise** (unlikely — the file is new to v2-azure and the original commit may also touch other files that exist on v2-azure): abort with `git cherry-pick --abort` and use the alternative path in Step 3.

- [ ] **Step 3 (alternative if cherry-pick fails): Recreate the file manually**

If cherry-pick conflicts on files other than the handoff doc itself:

```bash
git show origin/v3-microsoft-native:SOC-Automation-Project-to-Azure-Port.md > SOC-Automation-Project-to-Azure-Port.md
git add SOC-Automation-Project-to-Azure-Port.md
git commit -m "docs(v2-azure): add handoff doc on v2-azure branch (was on v3-microsoft-native only)"
```

This recreates only the file you care about, avoiding cross-branch noise.

- [ ] **Step 4: Verify file presence**

Run: `ls -la SOC-Automation-Project-to-Azure-Port.md`
Expected: File exists, ~10KB+ (the full handoff doc).

Run: `head -3 SOC-Automation-Project-to-Azure-Port.md`
Expected: First line is `# SOC-Automation-Project — Port to Azure` (or similar — confirm content match).

---

### Task 5: Sub-project status transition (draft → active)

**Files:**
- Modify: `vault/subprojects/2026-05-23-azure-port/spec.md` (frontmatter)
- Modify: `vault/subprojects/2026-05-23-azure-port/README.md` (frontmatter + Status section)

- [ ] **Step 1: Update spec.md frontmatter**

In `vault/subprojects/2026-05-23-azure-port/spec.md`, change line 2 from `status: draft` to `status: active`. Update line 3 `updated:` to today's date.

- [ ] **Step 2: Update README.md frontmatter + Status section**

In `vault/subprojects/2026-05-23-azure-port/README.md`, change line 2 from `status: draft` to `status: active`. Update line 3 `updated:` to today's date.

Update the "## Status" section near the bottom to reflect:
```markdown
## Status

- Brainstorming complete (2026-05-23). 8 clarifying questions resolved.
- Spec drafted at [[spec]].
- Implementation plan: [[plan]] (created 2026-05-23).
- Provisioning: in progress.
- Decommission: not started.
```

- [ ] **Step 3: Append log entry**

Append to `vault/log.md` (newest at top):
```markdown
YYYY-MM-DD — P2 (Azure Port) implementation kickoff; see [[subprojects/2026-05-23-azure-port/README]]
```
Replace `YYYY-MM-DD` with today's date.

- [ ] **Step 4: Commit**

```bash
git add vault/subprojects/2026-05-23-azure-port/spec.md vault/subprojects/2026-05-23-azure-port/README.md vault/log.md
git commit -m "docs(v2-azure): mark P2 spec + README active; log kickoff"
```

---

## Splunk VM (Tasks 6-12)

### Task 6: Provision `vm-soc-v2-splunk`

**Files:** none (portal-only)

- [ ] **Step 1: Open VM creation wizard**

Portal → "Create a resource" → "Ubuntu Server 24.04 LTS" (Microsoft-published image) → Create.

- [ ] **Step 2: Fill the Basics tab**

- Subscription: existing trial
- Resource group: `<rg-name-from-notes.md>`
- Virtual machine name: `vm-soc-v2-splunk`
- Region: Central US
- Availability options: No infrastructure redundancy required
- Security type: Standard (Trusted Launch OK if available; Standard is fine)
- Image: Ubuntu Server 24.04 LTS - x64 Gen2
- Size: **Standard_D4s_v3** (4 vCPU / 16 GiB)
  - Fallback if quota-blocked: `Standard_D2s_v3` (2 vCPU / 8 GiB) — Splunk runs but tighter
- Authentication type: SSH public key
- Username: `azureuser` (default; change if you prefer)
- SSH public key: paste your existing public key OR generate new with portal "Generate new key pair"
- Public inbound ports: None (we'll add NSG rules separately in Task 7)

- [ ] **Step 3: Fill the Networking tab**

- Virtual network: existing — `<vnet-name-from-notes.md>`
- Subnet: existing — `<subnet-name-from-notes.md>`
- Public IP: Create new (`vm-soc-v2-splunk-ip`)
- NIC network security group: **None** (NSG will be subnet-attached or created separately in Task 7)
- Accelerated networking: Off (D4s_v3 supports it but unnecessary for lab)
- Public inbound ports: None (defer to Task 7)

- [ ] **Step 4: Disks tab**

- OS disk type: Premium SSD (default)
- OS disk size: 64 GiB (default — sufficient for Splunk Free-tier 500 MB/day workload; bump to 128 GiB if you anticipate heavier index growth)

- [ ] **Step 5: Management tab — enable auto-shutdown**

- Auto-shutdown: On
- Shutdown time: 11:00 PM
- Time zone: your local
- Notification before shutdown: Off (or enable for email reminders if you prefer)

- [ ] **Step 6: Review + Create**

Click Review + Create. Validation runs.

Expected: Validation passes. Click Create. Deployment runs (~2-5 min).

- [ ] **Step 7: Verify VM is running**

Once deployment completes: Go to resource → Overview blade → status should be "Running." Note the public IP and private IP — record in notes.md.

- [ ] **Step 8: Update notes.md with VM info**

Append to `vault/subprojects/2026-05-23-azure-port/notes.md` under a new section:

```markdown
## VMs provisioned

| VM | Public IP | Private IP | Size | Provisioned |
|---|---|---|---|---|
| vm-soc-v2-splunk | `<public-ip>` | `<private-ip>` | Standard_D4s_v3 | YYYY-MM-DD HH:MM |
```

Commit:
```bash
git add vault/subprojects/2026-05-23-azure-port/notes.md
git commit -m "docs(v2-azure): record vm-soc-v2-splunk provisioning details"
```

---

### Task 7: Configure NSG rules for `vm-soc-v2-splunk`

**Files:** none (portal-only)

- [ ] **Step 1: Determine NSG attachment strategy**

Two options based on what you found in Task 3:
- **A:** Phase 1 has a *subnet-level NSG* — extend it with rules for the new VM. Cleanest, single place to manage.
- **B:** Phase 1 has *per-NIC NSGs* — create a new NSG for the new VM, attach to its NIC.

Use whichever matches existing Phase 1 pattern. The rule list below applies either way; only the attachment location differs.

- [ ] **Step 2: Add inbound rule: SSH from home IP**

Portal → NSG → Inbound security rules → + Add:
- Source: IP Addresses
- Source IP: `<your-home-IP>/32`
- Destination: IP Addresses → `<vm-soc-v2-splunk private IP>/32` (or "Any" if NSG is per-NIC scoped already)
- Service: SSH (auto-populates port 22, TCP)
- Action: Allow
- Priority: 1000 (or next available)
- Name: `allow-ssh-splunk-from-home`

Save.

- [ ] **Step 3: Add inbound rule: Splunk Web UI from home IP**

Same flow. Source `<home-IP>/32`, dest VM, port `8000` TCP. Name: `allow-splunkweb-from-home`. Priority: 1010.

- [ ] **Step 4: Add inbound rule: Splunk receiver port from vm-soc-v2-win**

Source: `<vm-soc-v2-win private IP>/32`, dest VM, port `9997` TCP. Name: `allow-uf-9997-from-win`. Priority: 1020.

- [ ] **Step 5: Verify rules visible**

NSG blade → Inbound security rules → confirm three new rules appear with the expected priorities and parameters.

- [ ] **Step 6: Test SSH access**

From your local machine:
```bash
ssh azureuser@<vm-soc-v2-splunk public IP>
```
Expected: SSH connection succeeds. You're now logged in to the Ubuntu VM.

If SSH fails: verify (a) your home IP hasn't rotated, (b) NSG rule source is correct, (c) the public IP is the expected one.

Stay logged in for Task 8.

---

### Task 8: Install Splunk Enterprise 10.2.2

**Files:** none (SSH session; runbook will capture in Task 25)

- [ ] **Step 1: Download Splunk Enterprise .deb**

In the SSH session:
```bash
wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-some-build-id-linux-amd64.deb'
```

**Note on version:** The exact build ID changes; the download URL on splunk.com may differ slightly. Verify by visiting https://www.splunk.com/en_us/download/splunk-enterprise.html, selecting "Linux .deb," and grabbing the wget URL from the "Download now via command line (wget)" link. Use that URL verbatim.

Expected: `splunk.deb` exists in home dir, size ~600+ MB.

- [ ] **Step 2: Install Splunk**

```bash
sudo dpkg -i splunk.deb
```
Expected: Splunk installs to `/opt/splunk`. dpkg exit 0.

- [ ] **Step 3: Start Splunk first time + accept license + set admin creds**

```bash
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd '<strong-temp-password>'
```

Replace `<strong-temp-password>` with a long random password. This sets the `admin` user's password.

Expected: Splunk starts; "All preliminary checks passed" → "Done" → "Splunk web interface is at http://<hostname>:8000".

- [ ] **Step 4: Configure boot-start**

```bash
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
```
Expected: "Init script installed at /etc/init.d/splunk." OR "Systemd service installed at /etc/systemd/system/Splunkd.service."

- [ ] **Step 5: Create `mydfir` user (v1's admin user, recreated here)**

```bash
sudo /opt/splunk/bin/splunk add user mydfir -role admin -password '<password-from-secrets-file>' -auth admin:<temp-password>
```

Use the `mydfir` user's password from the gitignored `SOC_Automation_Project/SOC-Automation-Project.md` secrets file (line referencing `mydfir` Splunk admin password).

Expected: "User mydfir added."

- [ ] **Step 6: Verify Splunk install**

In a browser: open `http://<vm-soc-v2-splunk public IP>:8000`.
Expected: Splunk login page.
Log in as `mydfir` / `<password>`.
Expected: Splunk dashboard loads.

In the Splunk UI: Settings → Licensing. Confirm:
- License group: Trial license group
- License expiration: ~60 days from today (NEW trial clock, not the Jun 24 local-VM one)
- Volume: 500 MB/day

- [ ] **Step 7: Configure Splunk to receive forwarder data on 9997**

In Splunk UI: Settings → Forwarding and receiving → Configure receiving → New Receiving Port → `9997` → Save.

Verify via SSH:
```bash
sudo netstat -tlnp | grep 9997
```
Expected: `splunkd` listening on `0.0.0.0:9997`.

---

### Task 9: Install Splunk add-ons (Sysmon TA + Windows TA)

**Files:** none

- [ ] **Step 1: Install `Splunk_TA_microsoft_sysmon` v5.0.0**

In Splunk UI: Apps → Find more apps → search "Splunk Add-on for Microsoft Sysmon" → install. Version should be **5.0.0** (verify in the app's Detail page).

Expected: Install completes; Splunk restart prompted. Accept restart.

- [ ] **Step 2: Install `Splunk_TA_windows` v10.0.1**

Same flow. Search "Splunk Add-on for Microsoft Windows" → install. Verify version **10.0.1**.

Expected: Install completes; restart again.

- [ ] **Step 3: Verify both add-ons present**

In SSH:
```bash
ls /opt/splunk/etc/apps/ | grep -E 'Splunk_TA_(microsoft_sysmon|windows)'
```
Expected: Both directories exist.

- [ ] **Step 4: Verify add-on versions**

```bash
grep -E 'version =' /opt/splunk/etc/apps/Splunk_TA_microsoft_sysmon/default/app.conf
grep -E 'version =' /opt/splunk/etc/apps/Splunk_TA_windows/default/app.conf
```
Expected: `version = 5.0.0` and `version = 10.0.1` respectively.

---

### Task 10: Create `mydfir-project` index

**Files:** none

- [ ] **Step 1: Create the index via Splunk UI**

Splunk UI: Settings → Indexes → New Index:
- Name: `mydfir-project`
- Index Data Type: Events
- Home Path: (default — leave as is)
- Cold Path: (default)
- Max raw data size: 500 MB (lab scope)
- Save.

Expected: Index appears in the indexes list with 0 events.

- [ ] **Step 2: Verify via SSH**

```bash
sudo /opt/splunk/bin/splunk list index -auth mydfir:<password> | grep mydfir-project
```
Expected: Index listed.

---

### Task 11: Re-create the 2 saved searches

**Files:** none in this task; the canonical definitions live in `vault/architecture/components/splunk.md`.

- [ ] **Step 1: Create `T1059.001 - PowerShell Encoded Command` (enabled)**

Splunk UI: Search & Reporting → search for the canonical SPL from `vault/architecture/components/splunk.md` (the regex matches encoded-command PowerShell invocations under `mydfir-project` Sysmon events).

Save As → Alert:
- Name: `T1059.001 - PowerShell Encoded Command`
- Description: "Detects T1059.001 PowerShell EncodedCommand via Sysmon ProcessCreate. Ported from v1; webhook → n8n on each result."
- Permissions: Owner = `mydfir`
- Alert type: Scheduled
- Cron: `*/5 * * * *`
- Trigger: For each result
- Throttling: none (per-result fires)
- **Trigger Actions: Webhook** → URL: `http://<placeholder>` (we'll update in Task 16 once n8n exists)
- Status: **Enabled**

Save.

- [ ] **Step 2: Create `Test-Brute-Force-External-Spoofed` (disabled)**

Same flow as Step 1 but:
- Name: `Test-Brute-Force-External-Spoofed`
- Description: "A1/A2 development saved search. Disabled at A2 closeout 2026-04-30. Known limitation: no threshold, fires per event. Kept for portfolio history."
- Cron: `* * * * *`
- Status: **Disabled**

Save.

- [ ] **Step 3: Verify both saved searches exist**

Splunk UI: Settings → Searches, reports, and alerts → confirm both visible with correct enable state.

---

### Task 12: Re-point `vm-soc-v2-win`'s Sysmon UF outputs + verify Splunk-only end-to-end

**Files:** none

- [ ] **Step 1: RDP to `vm-soc-v2-win`**

Use Phase 1's existing RDP access pattern (public IP + source-IP-restricted NSG rule). Log in.

- [ ] **Step 2: Locate `outputs.conf`**

PowerShell on the Windows VM:
```powershell
Get-ChildItem -Recurse -Filter outputs.conf 'C:\Program Files\SplunkUniversalForwarder\etc'
```
Expected: At least one file under `etc/system/local/outputs.conf` (or `etc/apps/<some-app>/local/outputs.conf`).

- [ ] **Step 3: Capture current outputs.conf for rollback**

Copy the file to a backup name: `outputs.conf.pre-p2-2026-05-23`. This preserves the v1-pointing config in case rollback is needed.

- [ ] **Step 4: Edit `outputs.conf` to point at new Splunk**

Open the file in a text editor (Notepad++ or similar with admin rights). Replace the `defaultGroup` server target with the new Splunk's private IP. Example:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = <vm-soc-v2-splunk private IP>:9997

[tcpout-server://<vm-soc-v2-splunk private IP>:9997]
```

Save (admin permission required).

**Note:** Keep the UF *only* pointing at the new Splunk — do not dual-output during this transition. The local Splunk continues running for rollback safety, but the active forwarding path moves to Azure. (If you want belt-and-suspenders dual-output, add a second `defaultGroup` member — but this complicates verification.)

- [ ] **Step 5: Restart SplunkForwarder service**

PowerShell as admin:
```powershell
Restart-Service SplunkForwarder
```
Expected: Service restarts. `Get-Service SplunkForwarder` shows Running.

- [ ] **Step 6: Verify forwarder connection in new Splunk**

Back in the new Splunk UI: Settings → Forwarder Management.
Expected: `vm-soc-v2-win` shows up as a connected forwarder, "Active" status.

(If it doesn't show up within ~30 sec: check NSG rule 9997 from win private IP, check UF logs at `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log` for connection errors.)

- [ ] **Step 7: Fire ATH Test 15 from `vm-soc-v2-win`**

In PowerShell on the Win VM (with Atomic Red Team installed per Phase 1):
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 15
```
Expected: Test runs; powershell.exe child process executes EncodedCommand.

- [ ] **Step 8: Verify event landed in new Splunk**

In new Splunk Search:
```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="*EncodedCommand*"
| head 5
```
Expected (within ~30 sec of firing): 1+ events visible matching the ATH process.

- [ ] **Step 9: Verify saved search fires within 5 min**

Within 5 minutes after Step 8: Splunk UI → Activity → Triggered Alerts. Expected: `T1059.001 - PowerShell Encoded Command` saved search shows a recent trigger (webhook will have failed since placeholder URL — that's expected).

**Splunk VM verification gate passed.** ✅ Local Splunk still running for rollback; UF feeds new Splunk; saved search detects.

- [ ] **Step 10: Log the milestone**

Append to `vault/log.md`:
```markdown
YYYY-MM-DD — P2 Task 12: vm-soc-v2-splunk verified end-to-end; ATH Test 15 → new Splunk index → T1059.001 saved search fires (webhook still placeholder)
```

Commit:
```bash
git add vault/log.md
git commit -m "docs(v2-azure): log Splunk VM verification milestone"
```

---

## n8n VM (Tasks 13-16)

### Task 13: Provision `vm-soc-v2-n8n` + NSG rules

**Files:** none (portal-only)

- [ ] **Step 1: Provision VM (same wizard as Task 6 but with different parameters)**

Portal → Create VM. Same RG, same VNet, same subnet, same image (Ubuntu 24.04 LTS). Differences:
- Name: `vm-soc-v2-n8n`
- Size: **Standard_D2s_v3** (2 vCPU / 8 GiB)
- Authentication: same SSH key as Task 6 (or new — your choice)
- Auto-shutdown: 11 PM local

Review + Create → Create. Wait for deployment.

- [ ] **Step 2: Record private + public IP in notes.md**

Append to the VM table in `vault/subprojects/2026-05-23-azure-port/notes.md`. Commit.

- [ ] **Step 3: Add NSG inbound rules for n8n**

Three rules (using the strategy from Task 7 Step 1):
- `allow-ssh-n8n-from-home`: home IP/32 → VM:22 TCP. Priority 1100.
- `allow-n8nweb-from-home`: home IP/32 → VM:5678 TCP. Priority 1110.
- `allow-webhook-from-splunk`: `<vm-soc-v2-splunk private IP>/32` → VM:5678 TCP. Priority 1120.

(Outbound traffic for Claude API / VT / AbuseIPDB is allowed by Azure's default outbound rule; no inbound rule needed for those.)

- [ ] **Step 4: Verify SSH**

```bash
ssh azureuser@<vm-soc-v2-n8n public IP>
```
Expected: Login succeeds.

---

### Task 14: Install docker + docker-compose + bring up n8n

**Files:** none (SSH session)

- [ ] **Step 1: Install docker engine**

```bash
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
Expected: Docker engine + compose-plugin installed; `docker --version` and `docker compose version` both report versions.

- [ ] **Step 2: Add `azureuser` to docker group**

```bash
sudo usermod -aG docker azureuser
exit  # close SSH; group membership refreshes on next login
```
Reconnect:
```bash
ssh azureuser@<vm-soc-v2-n8n public IP>
docker ps
```
Expected: Docker accessible without sudo.

- [ ] **Step 3: Create docker-compose.yml for n8n**

Use the same compose pattern v1 uses. Refer to the v1 host (192.168.129.132) for the canonical file — `scp` it over OR recreate from `vault/architecture/components/n8n.md` documentation. Likely content (adapt as needed from v1):

```yaml
version: '3.8'

services:
  n8n:
    image: n8nio/n8n:latest
    container_name: n8n
    restart: unless-stopped
    ports:
      - "5678:5678"
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=<from-secrets-file>
      - N8N_BASIC_AUTH_PASSWORD=<from-secrets-file>
      - N8N_HOST=<vm-soc-v2-n8n public IP>
      - WEBHOOK_URL=http://<vm-soc-v2-n8n public IP>:5678/
      - GENERIC_TIMEZONE=America/New_York
    volumes:
      - ~/.n8n:/home/node/.n8n
```

Save as `~/docker-compose.yml`.

**Pin to v1's image version if known** — check v1's docker-compose for the exact `n8nio/n8n:` tag. Reproducing v1 exactly avoids breaking-change surprises.

- [ ] **Step 4: Bring up n8n**

```bash
docker compose up -d
docker compose logs -f n8n
```
Expected: n8n starts; logs show "Editor is now accessible via: http://localhost:5678/" and similar. Press Ctrl-C to exit the log follow.

- [ ] **Step 5: Verify n8n accessible**

In a browser: `http://<vm-soc-v2-n8n public IP>:5678`.
Expected: n8n login page. Log in with the basic-auth creds.
Expected: n8n editor loads (empty workspace).

---

### Task 15: Import workflow + recreate 4 credentials

**Files:** none in this task (workflow JSON is in git at `JSON/SOC-Triage-v3.json`)

- [ ] **Step 1: Import SOC Triage v3 workflow**

n8n UI: top-right menu → Import from File → select `JSON/SOC-Triage-v3.json` from your local machine.

(If the file isn't on the n8n VM, scp it from your host or use the n8n "Paste JSON" import option.)

Expected: Workflow appears in editor. Nodes are visible; credentials show as "Credential not set" placeholders.

- [ ] **Step 2: Recreate 4 credentials**

For each credential, n8n UI → Credentials → New Credential:

| Credential | Type | Value source |
|---|---|---|
| `Claude API` (Anthropic) | HTTP Header Auth or Anthropic node-specific | API key from `SOC_Automation_Project/SOC-Automation-Project.md` |
| `VirusTotal API` | HTTP Header Auth | API key from same file |
| `AbuseIPDB API` | HTTP Header Auth | API key from same file |
| `DFIR-Iris API` | HTTP Header Auth | API key from same file (matches local IRIS — we'll update to Azure IRIS in Task 19) |

Save each. Then in each node that consumes a credential, ensure the dropdown points to the new credential.

- [ ] **Step 3: Verify workflow has all credentials wired**

n8n UI: open the workflow. Each HTTP Request node should show its credential populated (no red error icons on credential dropdowns).

- [ ] **Step 4: Activate the workflow**

Toggle the workflow to Active (top-right switch). The webhook URL becomes live.

- [ ] **Step 5: Note the webhook URL**

n8n UI: open the first webhook trigger node → copy the production webhook URL. Format: `http://<vm-soc-v2-n8n public IP>:5678/webhook/<unique-id>`.

Save this URL — needed in Task 16.

---

### Task 16: Update Splunk saved-search webhook to n8n + verify VM 2

**Files:** none

- [ ] **Step 1: SSH back to vm-soc-v2-splunk**

```bash
ssh azureuser@<vm-soc-v2-splunk public IP>
```

- [ ] **Step 2: Edit the saved search's webhook URL via Splunk UI**

Splunk UI: Settings → Searches, reports, and alerts → `T1059.001 - PowerShell Encoded Command` → Edit → Edit Actions → Webhook URL field. Replace placeholder with the n8n URL from Task 15 Step 5.

Save.

- [ ] **Step 3: Wait for next saved-search run OR fire ATH Test 15 manually**

The saved search runs every 5 min. To accelerate verification, fire ATH Test 15 again on `vm-soc-v2-win` (see Task 12 Step 7).

- [ ] **Step 4: Verify webhook delivery to n8n**

n8n UI: Executions tab. Within ~5 minutes of firing, an execution should appear for the workflow.

Click into the execution: confirm Splunk's payload was received, Claude triage step ran, enrichment steps ran. The IRIS step will fail (IRIS-in-Azure doesn't exist yet) — expected.

- [ ] **Step 5: Log the milestone**

Append to `vault/log.md`:
```markdown
YYYY-MM-DD — P2 Task 16: vm-soc-v2-n8n verified; Splunk webhook → n8n → Claude triage works; IRIS step expected failure
```

Commit.

---

## IRIS VM (Tasks 17-19)

### Task 17: Provision `vm-soc-v2-iris` + NSG rules

**Files:** none (portal-only)

- [ ] **Step 1: Provision VM**

Same wizard as Tasks 6 and 13. Differences:
- Name: `vm-soc-v2-iris`
- Size: `Standard_D2s_v3`
- Same RG/VNet/subnet, same SSH key, auto-shutdown 11 PM.

- [ ] **Step 2: Record IPs in notes.md, commit**

- [ ] **Step 3: Add NSG inbound rules**

- `allow-ssh-iris-from-home`: home IP/32 → VM:22 TCP. Priority 1200.
- `allow-irisweb-from-home`: home IP/32 → VM:443 TCP. Priority 1210.
- `allow-iris-from-n8n`: `<vm-soc-v2-n8n private IP>/32` → VM:443 TCP. Priority 1220.

- [ ] **Step 4: Verify SSH access**

```bash
ssh azureuser@<vm-soc-v2-iris public IP>
```
Expected: Login succeeds.

---

### Task 18: Install docker + bring up IRIS

**Files:** none

- [ ] **Step 1: Install docker (same as Task 14 Step 1)**

Repeat the apt install sequence from Task 14 Step 1.

- [ ] **Step 2: Clone DFIR-Iris docker source**

```bash
cd ~
git clone https://github.com/dfir-iris/iris-web.git
cd iris-web
git checkout v2.4.22
```

Expected: Repo cloned; checked out to tag matching v1's version.

- [ ] **Step 3: Configure environment**

DFIR-Iris uses `.env`. Copy the template and edit:
```bash
cp .env.model .env
nano .env
```

Set:
- `POSTGRES_PASSWORD` — strong password (record in notes.md or save to secrets file)
- `IRIS_ADM_PASSWORD` — IRIS admin password (from v1 secrets — keeps API key validity post-restore in Task 19)
- `IRIS_SECRET_KEY` — random 32+ char string
- Leave other settings at defaults for lab scope.

**Important:** Pin Postgres image version to v1's. Check `docker-compose.yml` → `db_server` service → `image:`. If v1 was on Postgres 12, set this to `postgres:12` (or whatever matches v1's `docker-compose.yml` from 192.168.129.133). Mismatched versions cause `pg_restore` failures.

- [ ] **Step 4: Bring up IRIS**

```bash
docker compose up -d
docker compose logs -f
```

Expected: All services come up (db_server, app, modules_iris, worker, rabbitmq, nginx_iris). The first startup takes ~2 min due to DB initialization.

Press Ctrl-C to exit log follow.

- [ ] **Step 5: Verify IRIS web UI accessible**

In a browser: `https://<vm-soc-v2-iris public IP>` (note HTTPS — IRIS uses self-signed cert; accept the warning).
Expected: IRIS login page. Log in with admin credentials from Step 3.

---

### Task 19: pg_dump + restore Postgres state from v1 IRIS

**Files:** none

- [ ] **Step 1: pg_dump from local v1 IRIS**

SSH to local IRIS (192.168.129.133):
```bash
ssh <iris-user>@192.168.129.133
docker exec -i <iris-db-container-name> pg_dump -U postgres iris_db > ~/iris-backup-2026-05-23.sql
```

Find the container name: `docker ps | grep db_server` on the v1 IRIS VM.

Expected: `iris-backup-2026-05-23.sql` exists; size > 0.

- [ ] **Step 2: scp dump to Azure IRIS**

```bash
scp ~/iris-backup-2026-05-23.sql azureuser@<vm-soc-v2-iris public IP>:~/
```
Expected: Transfer completes.

- [ ] **Step 3: Stop Azure IRIS app services (keep DB running)**

SSH to vm-soc-v2-iris:
```bash
cd ~/iris-web
docker compose stop app worker modules_iris nginx_iris
docker compose ps  # confirm db_server, rabbitmq still up
```

This ensures no writes happen during restore.

- [ ] **Step 4: Restore the dump**

```bash
cat ~/iris-backup-2026-05-23.sql | docker exec -i <azure-db-container-name> psql -U postgres -d iris_db
```

Find Azure DB container name: `docker compose ps` → `db_server`.

Expected: Restore completes; no errors. Some "already exists" warnings for default IRIS data may be normal — read carefully.

If restore fails on schema conflicts: this is the Postgres version mismatch risk. Verify Step 3 of Task 18 — was the image tag pinned to v1's version? If not, recreate the Azure DB with the correct version and retry.

- [ ] **Step 5: Restart IRIS app services**

```bash
docker compose start app worker modules_iris nginx_iris
docker compose logs -f
```

Expected: Services come back up cleanly. Confirm no errors related to schema or missing data.

- [ ] **Step 6: Verify cases / alerts present in Azure IRIS**

IRIS UI in browser: log in as admin. Navigate to Cases → Cases List.
Expected: All cases from v1 are present, including any case-level IOCs.

Navigate to Alerts → Alert Queue.
Expected: All historical alerts from v1 are present.

- [ ] **Step 7: Verify v1 API key still works (or regenerate)**

```bash
curl -k -H "Authorization: Bearer <v1-api-key-from-secrets>" https://<vm-soc-v2-iris public IP>/api/ping
```

Expected: Returns `{"status": "success", ...}`.

**If 401/403:** API key didn't survive the restore. Generate new in IRIS UI: User → API Key → Regenerate. Save new key to secrets file (or notes.md temporarily). Update n8n's IRIS credential in next step.

- [ ] **Step 8: Update n8n IRIS credential**

n8n UI: Credentials → DFIR-Iris API → Edit. Update:
- Host: `https://<vm-soc-v2-iris private IP>` (use private IP — n8n reaches IRIS over VNet)
- API key: from Step 7 (either same as v1 or newly regenerated)

Save.

- [ ] **Step 9: Fire ATH Test 15 — full end-to-end verification**

On `vm-soc-v2-win`:
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 15
```

Wait up to 5 minutes for the saved search to fire.

- [ ] **Step 10: Verify alert in Azure IRIS**

IRIS UI: Alerts → Alert Queue. Expected: A new alert appears with the T1059.001 details from Claude's triage, VirusTotal + AbuseIPDB enrichment, and a link back to the Splunk search.

**End-to-end pipeline verified in Azure.** ✅

- [ ] **Step 11: Log the milestone**

Append to `vault/log.md`:
```markdown
YYYY-MM-DD — P2 Task 19: End-to-end pipeline verified in Azure; ATH Test 15 → Splunk → n8n → Claude → IRIS alert lands
```

Commit.

---

## Decommission (Tasks 20-23)

### Task 20: Decommission local Splunk VM (192.168.129.131)

**Files:** none

- [ ] **Step 1: Confirm Azure Splunk verification gate is green**

Visual confirmation: re-fire ATH Test 15 if more than an hour has passed since Task 12. Confirm new event in Azure Splunk index.

- [ ] **Step 2: Power off local Splunk VM in VMware**

VMware Workstation/Player → right-click MyDFIR-Splunk → Power → Shut Down Guest.

Expected: VM stops cleanly.

- [ ] **Step 3: Locate VMDK files on host**

Find the VM's directory under VMware's default location (typically `C:\Users\<you>\Documents\Virtual Machines\MyDFIR-Splunk\` or `Documents\Virtual Machines\`). Note total folder size.

- [ ] **Step 4: Copy VMDK files to external SSD**

Plug in external SSD. Create a folder `SOC-Lab-Archives/MyDFIR-Splunk-2026-05-23/`. Copy the entire VM folder to the external SSD.

Expected: Copy completes; SSD folder contents byte-equivalent to source.

- [ ] **Step 5: Verify SSD copy integrity**

```powershell
Get-ChildItem -Recurse <source-folder> | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
Get-ChildItem -Recurse <ssd-folder> | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
```

Expected: Sizes match.

- [ ] **Step 6: Delete from VMware library**

VMware → right-click MyDFIR-Splunk → Manage → Delete from Disk.

Expected: VM removed; original folder deleted from C:.

- [ ] **Step 7: Confirm C: drive space recovered**

```powershell
Get-PSDrive C
```
Expected: Free space increased by approximately the size of the deleted VM folder.

- [ ] **Step 8: Log milestone**

Append to `vault/log.md`:
```markdown
YYYY-MM-DD — P2 Task 20: Local Splunk VM decommissioned; archived to external SSD; C: drive freed <X> GB
```

Commit.

---

### Task 21: Decommission local n8n VM (192.168.129.132)

**Files:** none

- [ ] **Step 1: Confirm Azure n8n verification gate (Task 16) was green** — visual.
- [ ] **Step 2-7: Repeat Task 20's steps for n8n VM (`MyDFIR-n8n` or whatever the VMware name is).**
- [ ] **Step 8: Log + commit.**

(Same pattern as Task 20. Folder name in archive: `n8n-2026-05-23/`.)

---

### Task 22: Decommission local IRIS VM (192.168.129.133)

**Files:** none

- [ ] **Step 1: Confirm Azure IRIS verification gate (Task 19) was green** — re-fire ATH if needed.
- [ ] **Step 2-7: Repeat Task 20's steps for IRIS VM.**
- [ ] **Step 8: Log + commit.**

(Same pattern. Folder name: `MyDFIR-Iris-2026-05-23/`.)

---

### Task 23: Decommission local Win10 endpoint (`DESKTOP-VNEF7PC`, 192.168.129.130)

**Files:** none

**Why last:** Win10 was functionally replaced in Phase 1 by `vm-soc-v2-win`, but kept around as a safety net. By this point, all v1 services are decommissioned, so the safety net is no longer relevant.

- [ ] **Step 1: Confirm `vm-soc-v2-win` is the active endpoint** — Sysmon UF was re-pointed in Task 12; verify it's still forwarding to Azure Splunk.
- [ ] **Step 2-7: Repeat Task 20's steps for Win10 VM.**
- [ ] **Step 8: Log + commit.**

(Archive folder: `DESKTOP-VNEF7PC-2026-05-23/`. This was the only Windows VM — be extra-careful with the export step; Windows VMDKs may include differencing disks that need consolidation first.)

---

## Wrap-up (Tasks 24-26)

### Task 24: Latency comparison capture + sub-project status update

**Files:**
- Create: `vault/subprojects/2026-05-23-azure-port/comparison-latency.md`
- Modify: `vault/subprojects/2026-05-23-azure-port/spec.md` (status → complete)
- Modify: `vault/subprojects/2026-05-23-azure-port/README.md` (status → complete + Status section)

- [ ] **Step 1: Re-fire ATH Test 15 with timestamp capture**

On `vm-soc-v2-win`, capture pre-fire timestamp:
```powershell
$t0 = Get-Date; "ATH fired at: $t0"
Invoke-AtomicTest T1059.001 -TestNumbers 15
```

- [ ] **Step 2: Capture timestamps at each pipeline step**

| Step | How to find timestamp |
|---|---|
| ATH fired | `$t0` from Step 1 |
| Splunk indexed | In Azure Splunk: `index=mydfir-project source="*Sysmon*" CommandLine="*EncodedCommand*" \| stats latest(_time) by _time \| head 1` |
| Saved search fired | Splunk UI → Activity → Triggered Alerts → timestamp of latest `T1059.001` trigger |
| n8n workflow executed | n8n UI → Executions → timestamp of latest execution |
| IRIS alert created | IRIS UI → Alerts → timestamp of latest alert |

- [ ] **Step 3: Write `comparison-latency.md`**

```markdown
---
status: active
updated: YYYY-MM-DD
sub_project: P2 (Azure Port)
related: [[README]], [[spec]]
---

# P2 Latency comparison: v1 (local VMware) vs P2 (Azure IaaS)

Captured during Task 24 with ATH Test 15 as the trigger event.

| Step | v1 (local VMware) baseline | P2 (Azure IaaS) | Delta | Notes |
|---|---|---|---|---|
| ATH fire → Splunk indexed | `<v1>` sec | `<p2>` sec | | |
| Splunk indexed → saved search fires | up to 5 min (cron) | up to 5 min (cron) | 0 | Identical cron schedule |
| Saved search → n8n received webhook | `<v1>` sec | `<p2>` sec | | |
| n8n webhook → Claude+enrich+IRIS write | `<v1>` sec | `<p2>` sec | | |
| **End-to-end (ATH → IRIS alert)** | `<v1>` total | `<p2>` total | | |

## Observations

- Index ingestion latency on Azure: `<observation>` — compare to v1.
- Network hops are all intra-VNet now (was intra-LAN before); expected similar or slightly faster.
- Any cold-start surprises: `<observation>`.

## Future comparison row (Phase 3 / Microsoft-native)

When Phase 3 ships (v3-microsoft-native branch), capture an additional row: ATH → Sentinel Incident → Logic App → Sentinel Update Incident. Compare against this baseline.
```

Fill in actual timestamps from Step 2. If you don't have v1 baseline numbers (this is the first capture), set v1 column to "not measured during v1 era; can be retroactively captured via VMware snapshot replay if needed" — honesty about data freshness matters more than fabricated baseline.

- [ ] **Step 4: Update spec.md frontmatter**

Set `status: complete`, update `updated:` date.

- [ ] **Step 5: Update README.md frontmatter + Status**

Set `status: complete`. Update the Status section:

```markdown
## Status

- Brainstorming complete (2026-05-23). 8 clarifying questions resolved.
- Spec: [[spec]] (status: complete).
- Implementation plan: [[plan]] (executed through Task 24).
- Provisioning: complete.
- Decommission: complete.
- Latency comparison: [[comparison-latency]].
- Runbook: [[runbook]] (created Task 25).
```

- [ ] **Step 6: Commit**

```bash
git add vault/subprojects/2026-05-23-azure-port/comparison-latency.md vault/subprojects/2026-05-23-azure-port/spec.md vault/subprojects/2026-05-23-azure-port/README.md
git commit -m "docs(v2-azure): capture P2 latency comparison + mark sub-project complete"
```

---

### Task 25: Write the operational runbook

**Files:**
- Create: `vault/subprojects/2026-05-23-azure-port/runbook.md`

- [ ] **Step 1: Write the runbook**

```markdown
---
status: active
updated: YYYY-MM-DD
sub_project: P2 (Azure Port)
related: [[README]], [[spec]], [[../../architecture/components/splunk]], [[../../architecture/components/n8n]], [[../../architecture/components/dfir-iris]]
---

# P2 Runbook — Operating the Azure-hosted SOC stack

## Daily ops

- **Auto-shutdown:** All 3 VMs shut down at 11 PM local (configurable per-VM in Azure portal → VM blade → Operations → Auto-shutdown).
- **Start before use:** Portal → each VM → Start. ~30 sec each to reach Running.
- **Forwarder reconnect:** When `vm-soc-v2-win` was offline, Sysmon UF backfills automatically on reconnect (default UF behavior).

## Common operations

### SSH access
- Splunk: `ssh azureuser@<vm-soc-v2-splunk-public-IP>`
- n8n: `ssh azureuser@<vm-soc-v2-n8n-public-IP>`
- IRIS: `ssh azureuser@<vm-soc-v2-iris-public-IP>`

If SSH fails after a home IP change: portal → NSG → update the source IP in the relevant rule.

### Web UI access
- Splunk: `http://<splunk-public-IP>:8000`
- n8n: `http://<n8n-public-IP>:5678`
- IRIS: `https://<iris-public-IP>` (accept self-signed cert warning)

### Restart services

| Service | How |
|---|---|
| Splunk | `sudo systemctl restart Splunkd` (or `/opt/splunk/bin/splunk restart` as splunk user) |
| n8n | SSH to n8n VM → `cd ~ && docker compose restart` |
| IRIS | SSH to IRIS VM → `cd ~/iris-web && docker compose restart` |

## Troubleshooting

### Splunk: T1059.001 alerts not firing
1. Check forwarder connection: Splunk UI → Settings → Forwarder Management. Is `vm-soc-v2-win` "Active"?
2. Check event arrival: `index=mydfir-project source="*Sysmon*" | head 5`. Recent events?
3. Check saved search: Settings → Searches → `T1059.001 - PowerShell Encoded Command` → confirm Enabled, Cron `*/5 * * * *`, Webhook URL points at current n8n endpoint.
4. Check webhook delivery: Splunk UI → Activity → Triggered Alerts → click the latest trigger. Should show webhook attempted.

### n8n: webhook fires but Claude triage errors
1. Open the failing execution in n8n UI.
2. Click the failed node → see error detail.
3. Common cause: Anthropic API key expired or rotated. Verify in Credentials → Claude API → Test connection.

### IRIS: alerts not appearing
1. n8n execution succeeded → IRIS API key/URL may be wrong. n8n Credentials → DFIR-Iris API → Test.
2. IRIS itself: SSH to IRIS VM → `docker compose ps`. All services Up?

## Secrets management

Secrets file at `SOC_Automation_Project/SOC-Automation-Project.md` (project root, gitignored). Contains:
- Splunk admin password (`mydfir` user)
- n8n basic auth creds
- IRIS admin + API key
- Anthropic API key
- VirusTotal API key
- AbuseIPDB API key
- VM SSH key locations

**Rotation reminder:** Last rotated 2026-05-18 (per workspace CLAUDE.md). Next due: TBD.

## Cost monitoring

- Auto-shutdown saves ~70% of VM costs.
- Premium SSD on Splunk's 64 GiB OS disk is the dominant non-compute cost.
- Estimated baseline: ~$X/month on trial subscription (run portal Cost Management → Cost analysis to confirm after first full month).

## Splunk Dev License watch

Submitted 2026-05-23 at dev.splunk.com. Trial expires ~60 days from Task 8 install. If dev license arrives before then → apply via Splunk UI → Settings → Licensing → Change license group → Enterprise → install license XML. If it doesn't arrive in time → reinstall Splunk for fresh trial, or evaluate Splunk Cloud Free.

## Rollback path (post-decommission)

External SSD at `SOC-Lab-Archives/<vm-name>-2026-05-23/` contains the v1 VMDKs. Restore = plug in SSD → VMware → File → Open → select `.vmx`. ~5-10 min per VM. Network reconfig may be needed if 192.168.129.0/24 has been reassigned.
```

Replace placeholders (`<vm-soc-v2-splunk-public-IP>` etc.) with actual values.

- [ ] **Step 2: Commit**

```bash
git add vault/subprojects/2026-05-23-azure-port/runbook.md
git commit -m "docs(v2-azure): add P2 operational runbook"
```

---

### Task 26: Update component docs + architecture diagram

**Files:**
- Modify: `vault/architecture/components/splunk.md`
- Modify: `vault/architecture/components/n8n.md`
- Modify: `vault/architecture/components/dfir-iris.md`
- Modify: `vault/architecture/current-state.md`

- [ ] **Step 1: Update `vault/architecture/components/splunk.md`**

In the file's "Configuration" section, replace the local Splunk endpoint with Azure. Keep historical context near the top:

```markdown
## Configuration (P2 / Azure)

| | |
|---|---|
| Host | `vm-soc-v2-splunk` (Azure VM, Central US) |
| Public Web UI | http://<azure-public-IP>:8000 |
| Private receiver | <azure-private-IP>:9997 |
| Admin user | `mydfir` (password in secrets file) |
| License | Enterprise Trial (new clock, fresh install Task 8) — Dev License pending |

## Migrated from v1 (decommissioned 2026-05-23)

Original local Splunk on `MyDFIR-Splunk` (192.168.129.131) was decommissioned during P2 Task 20. Historical config preserved in external-SSD archive.
```

(Keep the existing sections on apps, saved searches, Sysmon ingestion — they still describe the canonical SPL and add-on versions. Just update the host/IP references throughout.)

- [ ] **Step 2: Update `vault/architecture/components/n8n.md`**

Same pattern: add an "Azure" configuration section, mark v1 host as decommissioned.

- [ ] **Step 3: Update `vault/architecture/components/dfir-iris.md`**

Same pattern.

- [ ] **Step 4: Update `vault/architecture/current-state.md`**

If the diagram references specific IPs (192.168.129.x), replace them with the Azure VM names. The Mermaid diagram should reflect:
- `vm-soc-v2-win` (existing Phase 1 node) → `vm-soc-v2-splunk`
- `vm-soc-v2-splunk` → `vm-soc-v2-n8n` (webhook)
- `vm-soc-v2-n8n` → external services (Claude, VT, AbuseIPDB) + `vm-soc-v2-iris`

- [ ] **Step 5: Commit**

```bash
git add vault/architecture/components/splunk.md vault/architecture/components/n8n.md vault/architecture/components/dfir-iris.md vault/architecture/current-state.md
git commit -m "docs(v2-azure): update component docs + architecture diagram for P2 migration"
```

- [ ] **Step 6: Final log entry**

Append to `vault/log.md`:
```markdown
YYYY-MM-DD — P2 (Azure Port) COMPLETE. All 4 local VMs decommissioned; Azure stack operational; latency comparison captured; component docs + architecture diagram updated. See [[subprojects/2026-05-23-azure-port/README]].
```

Commit.

---

## Plan complete

After Task 26, the v1 → Azure IaaS port is complete:
- 3 Azure VMs operational (`vm-soc-v2-splunk`, `vm-soc-v2-n8n`, `vm-soc-v2-iris`).
- v1 pipeline functional end-to-end (ATH Test 15 → IRIS alert) in Azure.
- 4 local VMs decommissioned; C: drive freed.
- Sub-project status: complete; docs updated; runbook in place.

**Next:** Push branch + open PR (user-authorized). Then Phase 3 (Microsoft-native rewrite on `v3-microsoft-native` branch) resumes.
