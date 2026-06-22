# Honeypot Infrastructure (Phase 0A) — config-as-docs

Source of truth for rebuilding the caged Windows honeypot. Portal-driven; this file
records every setting so a rebuild is reproducible without re-deriving anything.

See the design spec and plan (in the parent workspace `docs/superpowers/`):
- Spec: `2026-06-22-honeypot-agentic-soc-design.md`
- Plan: `2026-06-22-honeypot-phase0a-infrastructure.md`

## Resources
- Resource group: `rg-honeypot` (Central US)
- VNet: (Task 2)
- NSG + rules: (Task 3 → see `nsg-rules.md`)
- VM: (Task 4)
- Budget/spend cap: (Task 5)
- Baseline snapshot: (Task 6/8)
- Sysmon config: (Task 7 → see `sysmon-config.xml`)
- UF inputs: (Task 8 → see `splunk-inputs.conf`)

## Rebuild
Restore the clean snapshot (Task 6) + re-confirm the NSG association (Task 3) +
auto-shutdown OFF + telemetry resumes in Splunk `honeypot` index (Task 9). Full
procedure in `RUNBOOK.md`.
