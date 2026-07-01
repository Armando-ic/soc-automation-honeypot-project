---
status: complete
updated: 2026-05-26
sub_project: P2 (Azure Port)
related: [[spec]], [[plan]], [[runbook]], [[notes]], [[comparison-latency]], [[../../../docs/SOC-Automation-Project-to-Azure-Port]]
---

# Sub-project P2 — Azure Port (v1 → Azure IaaS)

If you are a fresh Claude Code instance picking this up, **read the files in this folder in this order**:

1. **This README** — context, scope, where things stand
2. **`spec.md`** — what we're building and why (created during brainstorming 2026-05-23)
3. **`plan.md`** — implementation steps (created by the writing-plans skill after spec approval; not yet present)
4. **`runbook.md`** — how to operate the result (written during/after build; not yet present)
5. **`notes.md`** — gotchas, learnings, open questions (created during build; not yet present)

Then check `../../log.md` for any entries dated after this README's `updated` field — they tell you what's happened since.

## Branch context

This sub-project lives on the **`v2-azure`** branch (fresh from `main` as of 2026-05-23, after the branch restructure). The Phase 1 + deferred Microsoft-native SOAR work lives on the **`v3-microsoft-native`** branch (was previously `v2-azure`, renamed during Task 0 of this session).

If you don't see the project-root file `SOC-Automation-Project-to-Azure-Port.md` in your working tree, that's expected — it was committed to `v3-microsoft-native` before the restructure. The first pre-flight step in `spec.md` is to cherry-pick it onto `v2-azure`.

## Goal

Port the local-VMware SOC stack (Splunk + n8n + DFIR-IRIS) to Azure IaaS, then decommission the local VMs to free C: drive space. Phase 1's `vm-soc-v2-win` (already in Azure) stays as-is, with its Sysmon UF re-pointed to the new Splunk-in-Azure.

**Primary driver:** Free local C: drive space (user constraint).
**Secondary driver:** Broader Azure IaaS exposure beyond Phase 1's PaaS work.

## In scope (summary)

- Provision 3 new Azure Linux VMs: `vm-soc-v2-splunk`, `vm-soc-v2-n8n`, `vm-soc-v2-iris` (Central US, reuse Phase 1 RG/VNet).
- Splunk: fresh install (new 60-day trial clock) + Dev License application in parallel; re-create 2 saved searches; re-install 2 add-ons.
- n8n: fresh docker-compose redeploy; re-import workflow JSON from git; recreate 4 credentials from secrets.
- IRIS: fresh docker-compose redeploy; `pg_dump`/restore Postgres state.
- Re-point `vm-soc-v2-win` Sysmon UF to new Splunk.
- NSG rules: source-IP-restricted public IPs for SSH + web UIs; intra-VNet private IPs for the alert pipeline.
- End-to-end verification (ATH Test 15 → IRIS-in-Azure alert) with latency capture.
- Same-day decommission of 4 local VMs: verify → archive VMDK to external SSD → delete from VMware library.

## Out of scope (deliberately)

- Phase 3 Microsoft-native rewrite (Logic Apps + Sentinel incidents) — full spec + plan on `v3-microsoft-native`; resumes after P2 ships.
- A3 Enrichment Expansion (urlscan.io, URLhaus, IP2Location) — permanently deferred.
- Splunk historical data migration — fresh index; selective re-ingest post-P2 if needed.
- Azure Bastion / VPN — source-IP-restricted public IPs are sufficient.
- Multi-region / HA — single VM per service, Central US only.

## Key constraints

- **Splunk Enterprise Trial expires Jun 24, 2026** (~32 days from spec date). Drove the fresh-install decision; new install resets the 60-day clock.
- **No az CLI** — user opted out for v2-azure work. Azure portal only.
- **Trial subscription** — vCPU quota wall is a real risk (Phase 1 forced East US → Central US for this reason).
- **VM sizing preference** — D-series, not B-series. Pair with auto-shutdown.
- **Honesty preferred** — no flattery, push back on flawed premises.
- **No secrets in vault** — they live in the gitignored `../../../SOC-Automation-Project.md` at project root.

## Status

- **COMPLETE** — closed 2026-05-26 with Tasks 24–26.
- Brainstorming complete (2026-05-23). 8 clarifying questions resolved.
- Spec: [[spec]] — status complete.
- Implementation plan: [[plan]] — executed Tasks 1–26.
- Provisioning: complete (3 Azure VMs operational, P2 Tasks 6–19).
- Decommission: complete (4 local VMs archived to `F:\VMs\` and deleted from `C:\VMs`, P2 Tasks 20–23).
- Latency comparison: [[comparison-latency]] — IOC-rich fire captured 2026-05-26 with full enrichment trace.
- Runbook: [[runbook]] — operational, troubleshooting, 6 carry-forward gotchas + 21 catalog entries.
- Notes: [[notes]] — Task 24 IOC fire findings + decom phase gotchas appended 2026-05-26.

## References

- [[spec]] — full design with per-VM specs, NSG rules, sequencing, rollback.
- `../../../docs/SOC-Automation-Project-to-Azure-Port.md` — durable handoff doc with pivot story (cherry-pick from `v3-microsoft-native` as pre-flight).
- [[../../architecture/components/splunk]], [[../../architecture/components/n8n]], [[../../architecture/components/dfir-iris]] — v1 component definitions.
- [[../../architecture/current-state]] — v1 architecture diagram.
