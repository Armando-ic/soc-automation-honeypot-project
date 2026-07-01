# Honeypot Infrastructure (Phase 0A) — config-as-docs

Source of truth for rebuilding the caged Windows honeypot. Portal-driven; this file
records every setting so a rebuild is reproducible without re-deriving anything.

See the design spec and plan (in the parent workspace `docs/superpowers/`):
- Spec: `2026-06-22-honeypot-agentic-soc-design.md`
- Plan: `2026-06-22-honeypot-phase0a-infrastructure.md`

## Resources
- Resource group: `rg-honeypot` (Central US)
- VNet: `vnet-honeypot` · Central US · `10.66.0.0/24` · subnet `snet-honeypot` `10.66.0.0/27` · **Peerings: NONE (verified 2026-06-24)** · Private subnet: Enabled (egress only via the Task-4 public IP) · no overlap with SOC `10.0.0.0/16`
- NSG: `nsg-honeypot` → see `nsg-rules.md` (associated to `snet-honeypot`; 3 inbound + 5 outbound, created 2026-06-24)
- VM: `vm-honeypot-win` → **DONE 2026-06-25**, see `## VM (Task 4)` below. Public IP **`x.x.x.x`**.
- Budget/spend cap: **DONE 2026-06-25** — `budget-honeypot-monthly` $60/mo on `rg-honeypot`, actual alerts 50/90/100% → `owner@example.com`. (Alert-only; not a hard auto-stop.)
- Baseline snapshot: **DONE 2026-06-26** — `snap-honeypot-clean` (`rg-honeypot`, full, Standard_LRS) — clean instrumented baseline (Sysmon+UF already working). Rebuild source; see `RUNBOOK.md`.
- Sysmon config: **installed & logging (Task 7 DONE 2026-06-25)** → `sysmon-config.xml` (SwiftOnSecurity v74, schema 4.50) installed via Sysmon64 v15.21; Operational channel producing Id 1/22; Defender real-time disabled (intentional).
- UF inputs: **DONE 2026-06-26** → `splunk-inputs.conf` deployed; UF 10.4.0 on the VM forwards to `x.x.x.x:9997`; Splunk `honeypot` index + 9997 receiver + NSG rule (`allow-uf-9997-from-honeypot`) all live.

## v2-azure environment (telemetry target — Option A)
Honeypot stays UN-peered and forwards to Splunk's PUBLIC IP. Confirmed 2026-06-23:
- Splunk VM `vm-soc-v2-splunk` — public `x.x.x.x`, private `10.0.0.5` (private DENIED from honeypot).
- Splunk S2S receive port `9997` (confirm enabled at Task 8; TLS recommended).
- SOC VNet `vm-soc-v2-win-vnet` `10.0.0.0/16` (honeypot egress DENIES this whole range).
- SOC resource group `rg-soc-v2-azure-central-us` (Splunk NSG gets an inbound 9997-from-honeypot rule at Task 8).
- n8n webhook port `5678` (Splunk → n8n, existing).

## Quota preflight (Task 1 — DONE 2026-06-24)
- Binding limit was **Total Regional vCPUs (Central US) = 20/20 (100%)**, maxed by the existing
  D-series SOC VMs (DSv3 8 + DSv4 8 + Dasv7 4). BS-Family was `0/10` (room), but the regional umbrella blocked it.
- **Resolved: Total Regional vCPUs raised 20 → 28** (approved 2026-06-24) → **8 vCPUs free**.

## VM-size decision + AD-lab reclaim (2026-06-24)
- **B2s (v1, BS family)** has quota (`0/10`) but is **capacity-restricted** in Central US on this
  freshly-paid sub — won't deploy. So the original "use B2s" note is superseded.
- **Decision: honeypot = `Standard_B2als_v2`** (2 vCPU / 4 GiB AMD, ~$38/mo). Cheapest 24/7 option.
  Family = **Basv2** (the portal/usage label; the Quota REST resource name is `standardBasv2Family`).
  Fallback if Basv2 capacity is tight: `Standard_D2s_v4` (~$100/mo, reuses freed DSv4 quota).
- **Reclaim: deleted abandoned AD lab `rg-sysadmin-lab`** (CLIENT01/CLIENT02/DC01/FS01 = 4× D2s_v4 =
  8 vCPU DSv4, all deallocated). Whole-RG delete removed VMs + OS disks + NICs + public IPs in one shot.
  Result: **Total Regional 20 → 12 / 28** (16 free), **DSv4 8 → 0 / 10**. (Note: deallocation alone did
  NOT free vCPU quota — deletion did.) SOC RG `rg-soc-v2-azure-central-us` left untouched (4 VMs verified).
- **Basv2 quota request** 2026-06-24 (0 → 4) via Quota REST API (req `ae2f78c6-…`) was **declined by
  the auto-grant path** (`QuotaNotAvailableForResource`) even though the SKU is **unrestricted** in
  Central US (all 3 zones). Resolved by a **free quota support request** → **granted 2026-06-25**
  (Basv2 0 → 4; Total Regional umbrella also bumped to 32).

## VM (Task 4 — DONE 2026-06-25)
- `vm-honeypot-win` · `Standard_B2als_v2` (2 vCPU/4 GiB) · **Windows Server 2022 Datacenter Gen2**
  (`2022-datacenter-g2`) · security type **Standard** · `rg-honeypot` / `vnet-honeypot` / `snet-honeypot`.
- **Public IP (Standard, STATIC): `x.x.x.x`** · Private IP `10.66.0.4` · OS disk Standard SSD LRS.
- **NIC NSG = none** (subnet `nsg-honeypot` governs) · **Auto-shutdown OFF** · **Hardening: NONE (intentional)** · Power: running.
- Admin creds: in **gitignored `Personal/honeypot-vm-creds.txt`** (user `analyst`; password NOT recorded here).
- Provisioned via `az vm create` (after the AD-lab reclaim freed quota). Note: a first attempt
  accidentally used the Win Server **2025** image; deleted and recreated as **2022** per plan. Using
  `--security-type Standard` via CLI required registering `Microsoft.Compute/UseStandardSecurityType`
  (the portal does this silently).
- **`x.x.x.x` is the source IP for Splunk's inbound 9997 NSG allow-rule at Task 8.**

## Telemetry validation (Tasks 8–9 — DONE 2026-06-26)
End-to-end proof the honeypot host telemetry reaches Splunk. `index=honeypot | stats count by source sourcetype`:
- `WinEventLog:Security` (sourcetype `WinEventLog`) — 6,130 (logon activity incl. internet brute-force)
- `WinEventLog:System` (sourcetype `WinEventLog`) — 466
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (sourcetype `XmlWinEventLog`) — 3,330
Two bring-up bugs were fixed to get here (both = silent zero-events): the egress NSG port typo `997`→`9997`,
and the Sysmon `subscribeToEvtChannel errorCode=5` (stuck post-install subscription). Full diagnosis +
fixes in `RUNBOOK.md → Troubleshooting`. **Plan 0A done.**

## Rebuild
Restore the clean snapshot (Task 6) + re-confirm the NSG association (Task 3) +
auto-shutdown OFF + telemetry resumes in Splunk `honeypot` index (Task 9). Full
procedure in `RUNBOOK.md`.

## Falcon (Plan 0B)
- Trial: activated ~2026-06-28, **expires 2026-07-13** (15-day; **14 days remaining as of 2026-06-29**).
  Tier = Falcon platform trial (Go default — NGAV; free Insight XDR EDR module added at Task 4).
- Decision: trial-capture, keep/drop at trial end (no paid provisioning in 0B). Keep/drop checkpoint ~2026-07-12 (trial day ~14).
- API client: `honeypot-soar` · cloud = **us-2** · base URL `https://api.us-2.crowdstrike.com` ·
  scopes **Alerts:R/W, Hosts:R/W, Event streams:R** (created 2026-06-29, Plan 0B Task 2).
  Client ID/Secret live ONLY in `Personal/honeypot-vm-creds.txt` (gitignored — never committed/echoed).
- Sensor: **7.38.21003.0** installed 2026-06-29 via hands-on RDP. Windows hostname = **`vm-honeypot-win`**
  (external IP `x.x.x.x` confirmed in Host management). No reboot. Egress = existing `allow-web` (443).
  ✅ Tenant is honeypot-only: a personal Windows 11 workstation (`PERSONAL-WIN11`) briefly auto-enrolled and was
  **uninstalled 2026-06-29** (maintenance token), so a tenant-wide alert poll (0D-2) can't sweep it in. Host
  group `hg-honeypot` (Dynamic, hostname=`vm-honeypot-win`) + the Contain script are hostname-scoped anyway.
- Detect-only policy `honeypot-detect-only` (→ `hg-honeypot`) — **VALIDATED 2026-06-29**: a real EDR detection
  returned `pattern_disposition: 0` / all `pattern_disposition_details` false (detected, not blocked). See
  `falcon-validation.md` + `falcon-detect-only-policy.md`.
- Contain → Lift **proven 2026-06-29** (`normal→contained→normal`) via `scripts/falcon-contain-roundtrip.ps1`
  (hostname-scoped, run from a LOCAL machine) — the human-gated response Plan 0D-2 will use.
- ⚠️ Secret hygiene: the `honeypot-soar` secret was **rotated 2026-06-29** after an accidental inline paste;
  run API/Contain commands from a LOCAL trusted machine and load creds from the gitignored file (never inline).
- **0B done-when MET** (detect-only sensor + OAuth API + Contain→Lift). Docs: `falcon-setup-walkthrough.md`
  (steps), `crowdstrike-api-notes.md` (API), `falcon-validation.md` (evidence).
