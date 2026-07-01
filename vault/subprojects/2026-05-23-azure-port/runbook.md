---
status: active
updated: 2026-05-26
sub_project: P2 (Azure Port)
related: [[README]], [[spec]], [[notes]], [[comparison-latency]], [[../../architecture/components/splunk]], [[../../architecture/components/n8n]], [[../../architecture/components/dfir-iris]]
---

# P2 Runbook — Operating the Azure-hosted SOC stack

## At a glance

| VM | Public IP | Private IP | Role | Size |
|---|---|---|---|---|
| `vm-soc-v2-win` | `x.x.x.x` | `10.0.0.4` | Phase-1 Windows endpoint (Sysmon UF + ATH/synthetics) | Standard_D4as_v7 |
| `vm-soc-v2-splunk` | `x.x.x.x` | `10.0.0.5` | Splunk Enterprise 10.4.0 (Dev License, 10 GB/day) | Standard_D4s_v3 |
| `vm-soc-v2-n8n` | `x.x.x.x` | `10.0.0.6` | n8n 2.21.7 via docker compose (SOC Triage v3 workflow) | Standard_D2s_v3 |
| `vm-soc-v2-iris` | `x.x.x.x` | `10.0.0.7` | DFIR-IRIS 2.4.22 via docker compose | Standard_D2s_v3 |

**Resource group:** `rg-soc-v2-azure-central-us` (Central US).
**VNet/subnet:** `vm-soc-v2-win-vnet` / `default` (10.0.0.0/24); all 4 VMs share the subnet, intra-VNet traffic uses private IPs.
**Source IP for SSH/web UIs (NSG-restricted):** `x.x.x.x/32` — update via Azure portal NSG rules if it rotates.

## Daily ops

- **Auto-shutdown 11 PM Eastern** on all 4 VMs (Operations → Auto-shutdown). Saves ~70% of VM cost on the Trial subscription.
- **Start before use:** Azure portal → each VM → Start. ~30 s each to reach Running; parallelizable across all 4.
- **Sysmon UF backfill on reconnect** — when `vm-soc-v2-win` is restarted, the UF transparently catches up against the indexer on next service start; no manual intervention required.

## SSH / RDP / Web UI access

- **SSH key:** `C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem` (RSA, generated during Task 6, reused across all 3 Linux VMs). Login as `azureuser`.
  ```powershell
  ssh -i C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem azureuser@<public-ip>
  ```
- **Windows VM** — RDP via Azure portal Connect blade, **or** Azure portal → Operations → Run command → RunPowerShellScript for non-interactive tasks. **Never spawn GUI apps via Run Command** (Session 0 hangs the script forever and the VM must be restarted to clear it; see Gotcha §G1).
- **Web UIs (NSG-restricted to home IP):**
  - Splunk: `http://x.x.x.x:8000` (login: `mydfir` / secrets file)
  - n8n: `http://x.x.x.x:5678` (login: `owner@example.com` / secrets file)
  - IRIS: `https://x.x.x.x` (self-signed cert; login: `administrator` / secrets file)
- **If SSH fails after a home-IP change** — Azure portal → NSG → Inbound rules → update the `allow-ssh-*-from-home` source IP for each VM's NSG, then retry.

## Restart services

| Service | Command |
|---|---|
| Splunkd | `sudo systemctl restart Splunkd` on `vm-soc-v2-splunk` (~25 s downtime) |
| n8n | `cd ~ && docker compose restart` on `vm-soc-v2-n8n` (~5 s; restores webhook URL) |
| IRIS | `cd ~/iris-web && docker compose restart` on `vm-soc-v2-iris` (~30 s; 5 containers come up in sequence) |
| Splunk UF (Windows) | Run Command: `Restart-Service SplunkForwarder` |

## Common operations

### Manually fire a saved search for testing

Splunk's scheduled cron runs trigger alert actions automatically. **Manual dispatches via REST do NOT trigger actions unless told to** — pass `trigger_actions=1`:

```bash
curl -k -u mydfir:<password> \
  --data-urlencode 'output_mode=json' \
  --data-urlencode 'trigger_actions=1' \
  https://localhost:8089/servicesNS/mydfir/search/saved/searches/<name>/dispatch
```

Without `trigger_actions=1`, the search runs and returns results but no webhook fires. (See [[notes]] Task 19 gotcha #2.)

### Fire the demo IOC event (T1059.003 path)

Via Azure portal Run Command on `vm-soc-v2-win`:
```powershell
$guid = [guid]::NewGuid().ToString()
"Firing T1059.003 IOC demo at $(Get-Date -Format 'HH:mm:ss') UTC=$([DateTime]::UtcNow.ToString('HH:mm:ss')) guid=$guid"
cmd.exe /c "echo demo-$guid && echo IOC_IP=185.220.101.42 && echo IOC_HASH=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f && echo IOC_URL=http://malicious-test.invalid/payload && exit"
```

Within ~5 minutes (next `*/5` cron tick + 22 s active processing) you should see a new alert in IRIS titled `T1059.003 - Suspicious cmd.exe IOC References`. See [[comparison-latency]] for the full trace.

### Fire the PowerShell-encoded-command event (T1059.001 path)

```powershell
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "Task##-e2e-<guid>"'))
powershell.exe -NoProfile -EncodedCommand $enc
```

Same cron cadence; lands in IRIS as `T1059.001 - PowerShell Encoded Command` with empty `iocs[]`.

### List recent IRIS alerts

```bash
ssh -i .../vm-soc-v2-linux-key.pem azureuser@x.x.x.x
KEY=$(grep '^IRIS_ADM_API_KEY=' ~/iris-web/.env | cut -d= -f2)
curl -sk -H "Authorization: Bearer $KEY" \
  "https://localhost/alerts/filter?order_by=alert_creation_time&sort_dir=desc&per_page=10&page=1" | python3 -m json.tool
```

### List recent n8n executions

```bash
ssh -i .../vm-soc-v2-linux-key.pem azureuser@x.x.x.x
sqlite3 ~/.n8n/database.sqlite \
  "SELECT id, startedAt, stoppedAt, status, mode FROM execution_entity ORDER BY id DESC LIMIT 10"
```

(Install sqlite3 first time: `sudo apt-get install -y sqlite3`.)

## Troubleshooting

### Splunk: T1059.x alerts not firing

1. **Forwarder connection** — Splunk UI → Settings → Forwarder Management. Is `vm-soc-v2-win` listed and "Active"?
2. **Event arrival** — In Search: `index=mydfir-project source="*Sysmon*" | head 5`. Recent events visible?
3. **Saved search state** — Settings → Searches, reports, and alerts → confirm `enableSched=1`, `cron_schedule=*/5 * * * *`, `realtime_schedule=0`, `action.webhook.param.url` points at `http://10.0.0.6:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd`. (See Gotcha §S2.)
4. **Webhook delivery** — Activity → Triggered Alerts → click the latest trigger; shows webhook attempt + response.

### n8n: webhook fires but workflow errors

1. Open the failing execution in n8n UI → Executions → click.
2. Click the failed node for error detail.
3. **`'str' object has no attribute 'get'` at the "Add new Alert" IRIS node** — the `Add IOCs (JSON)` field must use `{{ $json.alert_iocs }}` not `{{ JSON.stringify($json.alert_iocs) }}`. See Gotcha §N1.
4. **Anthropic API key expired/rotated** — Credentials → Anthropic account → re-enter key from secrets file.

### IRIS: workflow succeeds in n8n but alert doesn't land

1. n8n Credentials → DFIR IRIS account → confirm Host = `https://10.0.0.7` (private IP), API Version = `2.0.4`, Use HTTP = OFF, Ignore SSL Issues = ON, Token from `~/iris-web/.env IRIS_ADM_API_KEY` on `vm-soc-v2-iris`.
2. SSH to IRIS VM → `cd ~/iris-web && docker compose ps` — all 5 containers (`db`, `rabbitmq`, `app`, `nginx` healthy, `worker`) should be "Up".
3. From n8n VM: `curl -k https://10.0.0.7/api/ping -H "Authorization: Bearer <key>"` should return `{"status":"success","message":"pong"}`. If not, the VNet rule or IRIS itself is the problem, not the credential.

### IOC enrichment fires but `iocs[]` is empty in IRIS

Symptom: Claude's prose description in IRIS clearly names IPs/hashes/URLs with AbuseIPDB + VirusTotal enrichment results, but `GET /alerts/<id>` returns `"iocs": []`.

**This is not a wiring bug.** It's a Claude system-prompt judgment call: when the LLM detects the event as a synthetic test (`demo-...` GUID, EICAR hash, `.invalid` URL, etc.), it suppresses structured IOC routing while still producing a thorough prose summary. A real-looking malicious event populates `iocs[]` normally.

Tracked as a system-prompt tuning opportunity; not P2 scope. See [[notes]] § "Empty structured `iocs[]` despite full prose IOCs" for the full root-cause analysis.

### Splunk Dev License expiration watch

- **Expires:** 2026-11-19 23:59:59 UTC.
- **Renewal window:** opens 2026-11-09 (10 days before expiry); same form at `dev.splunk.com/enterprise/`.
- **Fallback if renewal lags:** reinstall fresh (new 60-day Trial clock), or evaluate Splunk Cloud Free. Index data is non-load-bearing and can be re-ingested.

## Secrets management

Secrets live in the gitignored `SOC_Automation_Project/SOC-Automation-Project.md` at project root. Contains:

- Splunk `mydfir` admin password
- Splunk break-glass bootstrap admin password (24-char throwaway)
- n8n owner account credentials (native user management — `owner@example.com` / password)
- IRIS administrator password (set via `IRIS_ADM_PASSWORD` in `.env`)
- IRIS administrator API key (set via `IRIS_ADM_API_KEY` in `.env` — also available on disk at `~/iris-web/.env` on `vm-soc-v2-iris`)
- Anthropic API key
- VirusTotal API key
- AbuseIPDB API key
- VM SSH private-key location

**Rotation reminder:** last rotated 2026-05-18. Per workspace CLAUDE.md, migration to a true `.env` pattern is queued. **Never commit, echo, or paste these values in chat.**

## Cost monitoring

- Auto-shutdown (11 PM Eastern, all 4 VMs) keeps the Trial credit burn flat.
- Premium SSD on Splunk's 64 GiB OS disk is the dominant non-compute cost.
- Reconcile monthly: Azure portal → Cost Management → Cost analysis → filter to `rg-soc-v2-azure-central-us`.

---

## Gotcha catalog (carry-forward for rebuilds and operators)

Numbered for cross-reference. Each entry lists symptom + fix + the source-of-truth note that captured it.

### Splunk

- **§S1 — Splunk 10.4 hard-deprecates run-as-root.** `sudo /opt/splunk/bin/splunk start ...` aborts immediately. Use `sudo -u splunk /opt/splunk/bin/splunk ...` for first-start lifecycle. (See [[notes]] Task 8 gotchas.)
- **§S2 — `realtime_schedule=0` is required to keep `is_scheduled=1` stable across edits in 10.4** (gotcha first surfaced in 10.2.2, persists). Without it, the UI's "Real-Time Schedule" radio silently flips `is_scheduled=0` on the next edit. Confirm via `splunk btool savedsearches list <name>` (run as splunk user).
- **§S3 — REST API: `actions = webhook` is the master switch, not `action.webhook = 1`.** Either field alone won't fire the webhook. The `action.webhook = 1` flag alone DOES work when set via the UI (which writes both fields). When creating saved searches programmatically, set `actions=webhook` explicitly. (See [[notes]] Task 11 REST API gotchas.)
- **§S4 — `curl -d` does NOT URL-encode.** Semicolons in field values silently split fields. Use `--data-urlencode 'description=...'` for any free-text field.
- **§S5 — Manual saved-search dispatches do NOT trigger alert actions.** Pass `trigger_actions=1` in the dispatch POST body. (See [[notes]] Task 19 gotcha #2.)
- **§S6 — `dpkg -i splunk.deb` leaves bundled libs root-owned.** Run `sudo chown -R splunk:splunk /opt/splunk` before first start.
- **§S7 — Splunk Web takes ~10–15 s to bind `:8000` after `splunkd` starts.** Sleep before checking `ss -tlnp`.
- **§S8 — CLI noun rename in 10.4:** `splunk show licenser-localslave` (9.x) → `splunk list licenser-groups` and `splunk list licenses`.

### Splunk UF (Windows)

- **§U1 — Default service account `NT SERVICE\SplunkForwarder` cannot subscribe to the Sysmon channel** (`errorCode=5` in `splunkd.log`). **Fix: change service account to `LocalSystem`** via CIM (`sc.exe config` is fragile under PowerShell parsing):
  ```powershell
  $svc = Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'"
  Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ StartName="LocalSystem"; StartPassword="" }
  ```
- **§U2 — MSI requires `SPLUNKPASSWORD=` in 10.x silent install.** Without it, install fails. Useful flags for staged install: `AGREETOLICENSE=Yes RECEIVING_INDEXER=<ip>:<port> LAUNCHSPLUNK=0 SPLUNKPASSWORD=<pw>` — `LAUNCHSPLUNK=0` lets you drop `inputs.conf` before first start.
- **§U3 — UF's own helpers (`splunk-regmon`, `splunk-powershell`, `splunk-netmon`, `splunk-admon`) generate Sysmon EventCode=1 events** that the UF forwards to itself. Not a loop (Splunk filters/dedups) but expect them to dominate the first minutes after service start.

### n8n

- **§N1 — Pass `{{ $json.alert_iocs }}` raw to the "Add IOCs (JSON)" field of the `n8n-nodes-dfir-iris` community node v2.0.3. NOT `JSON.stringify(...)`.** The community node's `create.operation.ts` does not call `JSON.parse()` on this field — wrapping in `JSON.stringify` sends a string where IRIS expects an array of dicts, producing `'str' object has no attribute 'get'` from IRIS's Python backend. (See [[notes]] Task 19 gotcha #1.)
- **§N2 — n8n native user management, NOT `N8N_BASIC_AUTH_*`** for auth. The `N8N_BASIC_AUTH_*` env vars are deprecated since n8n 1.0+. Owner account at first browser visit; everything thereafter is form-based.
- **§N3 — n8n SPA serves at routed paths (`/setup`, `/workflow`, etc.), NOT at root `/`.** `curl http://localhost:5678/` returns 404 — expected. Use `/healthz` for liveness probes.
- **§N4 — Python 3 task runner warning at n8n startup is benign.** "Failed to start Python task runner ... Python 3 is missing." The JS Task Runner handles our workflows. Install python3 + restart container only if a future workflow needs Python code nodes.
- **§N5 — The `version: '3.8'` line in docker-compose.yml is obsolete in Compose v5.1.4.** Generates a warning but is ignored. Safe to omit in new compose files.

### DFIR-IRIS

- **§I1 — `depends_on:` workaround from 2026-04-29 / 2026-05-12 is OBSOLETE with modern docker compose v5.1.4 (plugin).** v1 used legacy `docker-compose 1.29.2` which had ordering / KeyError issues; the modern plugin handles short-form `depends_on` cleanly. Skip the awk pass — all 5 containers come up in correct order on first try.
- **§I2 — `IRIS_ADM_API_KEY` can be set explicitly in `.env`.** No need to bring IRIS up, scrape logs, and regenerate via UI. The `.env.model` documents this as optional (commented out by default); uncommenting and setting it gives a known API key from first start — clean for automation/reproducible rebuilds.
- **§I3 — `.env.model → .env` step is still required** (persists from v1 era). The repo doesn't ship a `.env`; only `.env.model`. Postgres won't start without the file existing.
- **§I4 — Benign DB log warning during first start:** `duplicate key value violates unique constraint groups_group_name_key Key (group_name)=(Analysts) already exists`. IRIS's init script tries to insert default groups and catches the conflict downstream. Don't chase it.

### Azure / Run Command

- **§G1 — Azure Run Command runs scripts as SYSTEM in Session 0 (no desktop).** **Never spawn GUI apps** (`notepad.exe`, `mspaint.exe`, etc.) — they hang forever waiting for a window that can't exist. Hang blocks any subsequent `-Wait` or `Out-Null` clause. Recovery requires a VM restart (no portal-side cancel for Run Command). Use console-only apps to fire process-create events: `Start-Process powershell.exe -ArgumentList ..., -Wait` works.
- **§G2 — PowerShell `@"..."@` here-strings in Run Command's textbox can break** if even trailing whitespace appears after the opening `@"`. The parser then treats subsequent `[...]` lines as type literals. **Safer pattern:** string arrays piped to `Set-Content`:
  ```powershell
  @('[Stanza]', 'key1 = value', 'key2 = value') | Set-Content -Path $p -Encoding ascii
  ```

### VMware decommission

- **§V1 — VMware "Delete from Disk" is selective.** It only deletes files registered in the VM's `.vmsd` snapshot index. `(1)`-suffix duplicates from prior copy/rename operations are orphans that survive — clean them up manually in File Explorer (the Splunk VM left behind 5.86 GB of these post-decom).
- **§V2 — Stale `.lck` folders from unclean shutdowns block robocopy.** Standard VMware troubleshooting: `Remove-Item -Recurse` on the `<vm-name>.vmx.lck` folder once the embedded PID is confirmed dead (`Get-Process -Id <pid>` returns nothing).

## Rollback path (post-decommission)

Local-VMware archives at `F:\VMs\<VM>\` (lift-and-shifted during Task 20–23 decommission, then deleted from `C:\VMs`):
- `F:\VMs\MyDFIR-Splunk\`
- `F:\VMs\MyDFIR-n8n-VM-v2\`
- `F:\VMs\MyDFIR-DFIR-IRIS-VM-v2\`
- `F:\VMs\MyDfir-Windows10-v2\`

Restore = VMware Workstation → File → Open → select the relevant `.vmx`. Network reconfig may be needed if `192.168.129.0/24` has been re-leased by something else.

The three out-of-scope VMs left in `C:\VMs` (post-decom, not part of P2 archive):
- `C:\VMs\MyDfir-FlareVM\`
- `C:\VMs\MyDfir-Remnux\`
- `C:\VMs\MyDfir-Zeek-Suricata\`

These remain on C: by design — they're separate from the SOC pipeline.
