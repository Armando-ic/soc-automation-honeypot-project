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
- VM: (Task 4 — size **`Standard_B2als_v2`** decided 2026-06-24; pending Basv2 quota)
- Budget/spend cap: (Task 5)
- Baseline snapshot: (Task 6/8)
- Sysmon config: **authored & version-pinned** → see `sysmon-config.xml` (SwiftOnSecurity baseline; Task 7 — on-VM install pending the VM)
- UF inputs: **authored** → see `splunk-inputs.conf` (Sysmon+WinEventLog → `honeypot` index; Task 8 — on-VM UF install + Splunk-side index/NSG pending the VM)

## v2-azure environment (telemetry target — Option A)
Honeypot stays UN-peered and forwards to Splunk's PUBLIC IP. Confirmed 2026-06-23:
- Splunk VM `vm-soc-v2-splunk` — public `20.236.193.253`, private `10.0.0.5` (private DENIED from honeypot).
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
- **Basv2 quota request submitted** 2026-06-24 (0 → 4) via Quota REST API, request id
  `ae2f78c6-cace-43d1-9c3a-fdf02e70e580` — status InProgress at submit; VM deploy gated on it landing.

## Rebuild
Restore the clean snapshot (Task 6) + re-confirm the NSG association (Task 3) +
auto-shutdown OFF + telemetry resumes in Splunk `honeypot` index (Task 9). Full
procedure in `RUNBOOK.md`.
