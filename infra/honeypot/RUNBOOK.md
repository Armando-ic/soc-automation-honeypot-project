# Honeypot Lab-Ops Runbook (Phase 0A)

Operating discipline for the caged Windows honeypot `vm-honeypot-win` (public `128.203.185.25`),
the source-of-truth ops doc (Layer 3 of the design spec's process engineering). Phase 0A complete
2026-06-26.

## Rebuild (on compromise or drift)
The rebuild source is the snapshot **`snap-honeypot-clean`** (`rg-honeypot`, taken 2026-06-26 — clean,
fully instrumented: Sysmon + Universal Forwarder already installed and forwarding).
1. (Optional, for forensics) Snapshot the OWNED disk first: `snap-honeypot-owned-YYYYMMDD`.
2. Create a new managed disk from `snap-honeypot-clean`, then swap it onto `vm-honeypot-win`
   (or recreate the VM from it). Security type must stay **Standard** (matches the live VM).
3. Re-confirm: NIC NSG = none (subnet `nsg-honeypot` governs), **auto-shutdown OFF**, Public IP still
   `128.203.185.25` (Static).
4. Confirm telemetry resumes: `index=honeypot | stats count by source sourcetype` shows all three
   sources within ~15 min (Security/System as `WinEventLog`, Sysmon as `XmlWinEventLog`).
5. If Sysmon specifically is missing after a rebuild, see **Troubleshooting → Sysmon 0 events** below.

## Lifecycle cadence
- Clean baseline = `snap-honeypot-clean`. Expose 24/7 (auto-shutdown OFF).
- On suspected full compromise: snapshot the owned disk for forensics → rebuild (see ## Rebuild).
- Cadence: review weekly; rebuild on confirmed compromise or monthly, whichever comes first.

## Malware handling
- Hash-first, static-only, **NEVER execute** a captured sample on a connected host.
- Store samples zipped + password-protected in an isolated location; record only the **SHA256** in the repo.
- The honeypot's egress is capped (Splunk:9997, DNS, web:443 only) so a running sample can't reach
  arbitrary C2 ports — but treat the box as hostile regardless.

## Cost governance
- Budget: **$60/mo on `rg-honeypot`** (`budget-honeypot-monthly`, alerts 50/90/100% → `owner@example.com`).
  Alert-only (not a hard stop). Expected burn ~$48/mo (B2als_v2 + Standard-SSD disk + Standard public IP).
- "Honeypot owned" is **expected**, not an incident. A surprise cost spike (e.g. mining) = check egress
  logs + rebuild; review the spend cap weekly.
- The SOC stack (Splunk/n8n/Iris) auto-shuts at **23:00 ET** to save cost; the honeypot runs 24/7 and the
  UF **queues on disk** while Splunk is down, backfilling when it returns (accepted "batched ingestion"
  posture — see the spec's open issue). Start Splunk manually for live triage/demos.

## Data hygiene
- **ZERO real secrets/creds** ever placed on the honeypot.
- VM admin creds live ONLY in the gitignored `Personal/honeypot-vm-creds.txt` (never committed; `Personal/`
  is in `.gitignore`). Attacker-generated data may be retained for analysis.

## Distinguish: lab event vs real incident
- **"Honeypot got owned"** (attacker logs in, runs tools, drops malware) = **expected lab event** →
  triage/observe, rebuild on cadence.
- **"Pipeline broke"** (no new telemetry in Splunk `index=honeypot`) = **real incident** → debug the
  UF / NSG / Splunk path (see Troubleshooting). Don't confuse the two.

## Troubleshooting (hard-won, 2026-06-26)
Two non-obvious failure modes cost real time during Phase 0A bring-up — both produce **silent zero
events** with no obvious error:

### 1. Zero events at all (UF "Configured but inactive forwards")
Cause: the honeypot egress NSG `allow-splunk-telemetry` rule had a **port typo — `997` instead of
`9997`**. Because the egress posture is `deny-all-other-egress` (prio 4096), one wrong digit on the only
telemetry port silently dropped every forwarder packet *before it left the subnet* — no error anywhere.
- Diagnose: on the honeypot, `Test-NetConnection 20.236.193.253 -Port 9997` → `TcpTestSucceeded:False`.
- Fix: `az network nsg rule update -g rg-honeypot --nsg-name nsg-honeypot --name allow-splunk-telemetry --destination-port-ranges 9997`.
- Lesson: with a tight deny-all egress, verify the *exact* allowed port; failures are silent.

### 2. Security/System flow but Sysmon = 0 events ("subscribeToEvtChannel errorCode=5")
Symptom: `index=honeypot` has `WinEventLog:Security`/`:System` but no
`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`; `splunkd.log` shows
`subscribeToEvtChannel: Could not subscribe to ... 'Microsoft-Windows-Sysmon/Operational': errorCode=5`.
- `errorCode=5` = ACCESS_DENIED, BUT in our case the UF already ran as **LocalSystem** and the Sysmon
  channel SDDL already granted SYSTEM full (`(A;;0xf0007;;;SY)`) — the ACL was a red herring.
- The real fix that stuck: **re-apply the channel access and restart the forwarder**, which cleared a
  stuck subscription state left from the first-launch (post-install) failure:
  ```powershell
  wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)"
  Restart-Service SplunkForwarder -Force
  ```
- Verify (auth-free): a read checkpoint appears at
  `...\SplunkUniversalForwarder\var\lib\splunk\modinputs\WinEventLog\Microsoft-Windows-Sysmon_Operational`
  and its `LastWriteTime` advances → the UF is reading the channel.
- If running the UF as a low-priv/virtual account instead of LocalSystem, the cleaner fix is to add that
  account to **Event Log Readers** (or grant it in the channel SDDL).

## Remote ops note
Honeypot OS-level changes can be run without RDP via **Azure Run Command**
(`az vm run-command invoke -g rg-honeypot -n vm-honeypot-win --command-id RunPowerShellScript --scripts @<file>`),
which executes PowerShell as SYSTEM through the guest agent.
