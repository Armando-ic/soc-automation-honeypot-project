# Honeypot Infrastructure (Phase 0A) — config-as-docs

Source of truth for rebuilding the caged Windows honeypot. Portal-driven; this file
records every setting so a rebuild is reproducible without re-deriving anything.

See the design spec and plan (in the parent workspace `docs/superpowers/`):
- Spec: `2026-06-22-honeypot-agentic-soc-design.md`
- Plan: `2026-06-22-honeypot-phase0a-infrastructure.md`

## Resources
- Resource group: `rg-honeypot` (Central US)
- VNet: `vnet-honeypot` · Central US · `10.66.0.0/24` · subnet `snet-honeypot` `10.66.0.0/27` · **Peerings: NONE (verified 2026-06-24)** · Private subnet: Enabled (egress only via the Task-4 public IP) · no overlap with SOC `10.0.0.0/16`
- NSG + rules: (Task 3 → see `nsg-rules.md`)
- VM: (Task 4)
- Budget/spend cap: (Task 5)
- Baseline snapshot: (Task 6/8)
- Sysmon config: (Task 7 → see `sysmon-config.xml`)
- UF inputs: (Task 8 → see `splunk-inputs.conf`)

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
- B2s honeypot (2 vCPU) fits; headroom remains for the later Qdrant VM. Use **B2s (BS family)**; avoid Bsv2 (`0/0` quota).

## Rebuild
Restore the clean snapshot (Task 6) + re-confirm the NSG association (Task 3) +
auto-shutdown OFF + telemetry resumes in Splunk `honeypot` index (Task 9). Full
procedure in `RUNBOOK.md`.
