# SOC-Automation-Project — Port to Azure

> **⚠️ SUPERSEDED (2026-05-26).** The P2 Azure Port shipped 2026-05-26 — the SOAR stack (Splunk + n8n + DFIR-IRIS) is live on Azure IaaS and the local VMs were decommissioned. This file is kept as the port's historical handoff; for current state see [current-state.md](../vault/architecture/current-state.md). Active work is now the honeypot agentic-SOC upgrade.

> **Read this first.** This is the durable handoff for porting the existing local-VMware SOC Automation Project (Splunk + n8n + DFIR-IRIS) onto Azure IaaS. Once that's stable and the local VMs can be decommissioned, the existing Microsoft-native rewrite work (currently deferred) resumes as the *next* phase after this one.

---

## Status

| | |
|---|---|
| **Created** | 2026-05-23 |
| **Active** | No — superseded; the P2 Azure Port shipped 2026-05-26 (see the banner above) |
| **Defers** | The v2-azure Microsoft-native rewrite (full spec + plan exist; resumes after this port is stable) |
| **Branch (current)** | `v2-azure` (where this handoff doc was committed). Migration work should likely happen on a NEW branch from `main` — see "Open questions" §3. |

---

## Why this exists — the pivot story

On 2026-05-22 (day of Phase 1 shipping), the user locked this decision in the v2-azure README:

> **Endpoint approach:** Pure Azure (new Azure Windows VM ingesting via AMA). **Not hybrid; not forwarding from the existing on-prem Win10. Cleanest parallel-implementation narrative.**

That locked-in approach drove Phase 1 (the Azure Windows VM, AMA, DCR, Sentinel, KQL detection — all already shipped). On 2026-05-23, the user reversed that decision mid-session while we were executing the Phase 2 (Microsoft-native SOAR) plan.

**The reversal — stated in the user's own words:**

> "I want to move the entire SOC-Automation-Project into Azure! I really do need my computer space freed, after we move all vms to azure and confirm they work we will then shift focus on what we are to do with our local vm files. My initial plan on why I wanted to learn and use azure was to expose myself to microsoft azure and its services. Moving the VMs over was just a secondary thought I had after realizing that I am running out of C Drive space, I do not want to move any VM files my any other drive on my PC."

**The two drivers, in priority order:**

1. **Primary:** Free up C: drive space (immediate, blocking).
2. **Secondary:** Broader Azure exposure (always was a goal; this serves it).

**Sequence the user wants:**

| Phase | Status | What it is |
|---|---|---|
| Phase 1 | ✅ DONE (2026-05-22) | Azure foundation: Sentinel + Log Analytics workspace + `vm-soc-v2-win` + AMA + DCR + T1059.001 KQL detection. Lives on `v2-azure` branch. |
| **Phase 2 — Port to Azure** | 🟡 **THIS DOC's SCOPE** | Lift-and-shift Splunk + n8n + DFIR-IRIS from local VMware to Azure IaaS VMs. Verify v1 pipeline (Splunk webhook → n8n → Claude → IRIS) still works end-to-end. Then decommission local VMs. |
| Phase 3 — Microsoft-native rewrite | 🔵 DEFERRED | Logic Apps + Sentinel-native incidents replacing n8n + IRIS. Full spec + plan already exist (see "Deferred artifacts" below). Resumes after Phase 2 is stable. |

---

## Deferred artifacts — do NOT execute until Phase 2 ships

These were written 2026-05-23 *before* the reversal. They are correct in content but were misnumbered as "Phase 2." They become Phase 3 once this port is done:

- **Spec:** [`v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md`](v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md) — frontmatter status updated to `deferred` with cross-reference back here.
- **Plan:** [`v2-azure/plans/2026-05-23-phase-2-soar-logic-app-plan.md`](v2-azure/plans/2026-05-23-phase-2-soar-logic-app-plan.md) — same.

Both remain on the `v2-azure` branch. Don't delete or move them — they're the next-next thing to do.

---

## In-scope VMs for this port

Three Linux VMs currently running locally on VMware NAT subnet `192.168.129.0/24`:

| Local VM | Local IP | Service | Stack |
|---|---|---|---|
| Splunk (`MyDFIR-Splunk`) | 192.168.129.131 | Splunk Enterprise 10.2.2 | Ubuntu Server (per `vault/architecture/components/splunk.md`) |
| n8n | 192.168.129.132 | n8n via docker-compose (currently SOC Triage v3 active) | Ubuntu Server 24.04 |
| DFIR-Iris | 192.168.129.133 | DFIR-Iris 2.4.22 via docker-compose | Ubuntu (verify version during brainstorm) |

**Phase 1 already replaced the Win10 endpoint** with the Azure-native `vm-soc-v2-win`. If the local Win10 VMware machine still exists and consumes C: drive space, also consider it for decommission — but it's already functionally replaced, so no migration work is needed for it.

State that needs to come along:

- **Splunk:** indexes (multi-GB), saved searches, alerts, dashboards, configured data inputs, Splunk_TA_microsoft_sysmon add-on, license. The T1059.001 saved search is the critical one (v1 v3 pipeline depends on it).
- **n8n:** workflow JSON ([`JSON/SOC-Triage-v3.json`](JSON/SOC-Triage-v3.json) — already in git), credentials (4 of them — recreate from gitignored secrets file), pinned webhook test data.
- **DFIR-Iris:** Postgres database (cases, alerts, evidence), API keys, customer/severity config, SSL cert.

---

## Constraints carried over from Phase 1

1. **Subscription:** Trial on `owner@example.com`. Has hit vCPU quota walls before (East US was zero quota; forced move to Central US in Phase 1). **Three more Linux VMs may bust quota again — validate before committing to VM sizes.**
2. **Region:** Central US (matches Phase 1 + avoids cross-region traffic to existing `law-soc-v2-azure`).
3. **VM sizing preference (user-stated):** Default to `D4s_v3` or equivalent (4 vCPU / 16 GiB), not B-series minimums. Pair with auto-shutdown. Already noted in memory.
4. **Secrets:** `SOC_Automation_Project/SOC-Automation-Project.md` (gitignored, plaintext). Same Anthropic/VT/AbuseIPDB/IRIS keys used by v1 will be needed by the migrated stack. **Do not commit, echo, or paste any of those values.**
5. **No az CLI** — user opted out for the v2-azure work and explicitly confirmed this preference. Portal-driven throughout. (PowerShell-based REST calls may also be out — confirm with user before using any auth-requiring CLI.)
6. **Honesty preferred** — no flattery, no hallucination, push back on flawed premises. See [memory: `feedback_honesty.md`](../../../Users/Owner/.claude/projects/f--Claude-Code-Skills-Learning/memory/feedback_honesty.md).

---

## Starting instructions for the next instance

**The very first thing to do:**

1. Read this entire document.
2. Read [workspace CLAUDE.md](../CLAUDE.md) — has the "Active direction" section that points back here.
3. Read [project CLAUDE.md](CLAUDE.md) — project-level cross-cutting context.
4. Read [v2-azure/README.md](v2-azure/README.md) — has the locked-decisions section with the reversal recorded.
5. Skim the deferred spec ([`v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md`](v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md)) to understand what eventually resumes after Phase 2.
6. **Then invoke `superpowers:brainstorming`** to design the migration. The scope, approach, branching strategy, and order have NOT been brainstormed yet — start there.

**Topics the brainstorming should cover:**

- **Per-VM migration approach.** Lift-and-shift disk image import (VMware → VHD → Azure Managed Disk) vs fresh provision + reinstall + data import. Each VM may have a different right answer. Splunk has license + index considerations; n8n is mostly docker-compose redeploy + workflow re-import; IRIS is docker-compose + Postgres dump/restore.
- **State migration.** Splunk indexes (largest blob, possibly skip and re-ingest); IRIS Postgres `pg_dump`; n8n credentials (recreate from the gitignored secrets file).
- **Networking.** Azure VNet + subnet mimicking 192.168.129.0/24. NSG rules (which ports need to be open between the three VMs? Splunk 8089/8000, IRIS 443, n8n 5678, etc.). Public IPs vs private only — Phase 1 endpoint had public RDP restricted by source IP; consider similar for this.
- **Branch strategy.** New `azure-migration` branch from `main`? Or work on `main` directly since this is migrating v1, not adding a new feature? (Recommendation: new branch from `main`. The `v2-azure` branch is for the eventual Microsoft-native rewrite and shouldn't be conflated.)
- **Decommission order.** Once each Azure VM is verified working, when does the local VMware VM get powered off / disk freed? User has stated: only AFTER all VMs work in Azure, and they don't want to move VM files to other local drives — they want them off the PC entirely. Consider an external SSD/archive for the disks before final delete, in case rollback is needed.
- **Success criterion for Phase 2.** Fire ATH Test 15 from any Windows endpoint → Splunk-in-Azure index it → n8n-in-Azure webhook fires → Claude triages → DFIR-Iris-in-Azure receives alert. End-to-end same as v1 v3, just running in Azure. Probably want to capture the latency for comparison against v1's local-VMware baseline (and eventually Phase 3's Microsoft-native numbers).

---

## Open questions for the next instance to surface

1. **Win10 VMware endpoint** — does it still exist and consume disk space, or has it been deleted since Phase 1 replaced it functionally? If it still exists, decommissioning it is part of Phase 2 cleanup.
2. **Splunk license** — single-instance dev license? Trial? Free tier (500 MB/day cap)? Determines whether we can spin up a new Splunk in Azure or need to migrate the existing install via disk import.
3. **Branch strategy** — see brainstorming topics above.
4. **Naming convention** for the 3 migrated VMs. Suggested: `vm-soc-splunk-azure`, `vm-soc-n8n-azure`, `vm-soc-iris-azure` (parallel to existing `vm-soc-v2-win`). Or use `v1-` prefix to mark them as "v1 in Azure" vs the v2 endpoint. User's call.
5. **vCPU quota check** — run a quota check in Central US before committing to VM sizes. Phase 1's `Standard_D4as_v7` is 4 vCPUs; 3 more = 12 more vCPUs needed. Free Trial caps can be tight.
6. **Data migration approach for Splunk indexes** — full migration (preserve history) vs fresh-start + reingest from CSVs/forwarders. Depends on how much of the Splunk training curriculum's data the user needs preserved.

---

## What was happening when the pivot fired (so you understand the abandoned-mid-execution state)

The 2026-05-23 session went:

1. User restarted from prior session's notes ("continuing v2-azure Phase 2 work").
2. Got blocked briefly on Microsoft Defender XDR portal login (resolved — user already had access; my Claude diagnosis was wrong, corrected in conversation).
3. Brainstormed the Microsoft-native SOAR design → wrote spec (commit `75a5207`).
4. Wrote implementation plan (commit `ee60b0e`).
5. Amended plan for portal-only paths (no az CLI) (commit `b418795`).
6. Started executing Task 1 of the Microsoft-native plan — got Step 1 done (branch state verified), Step 2 pending on user.
7. **User realized the actual desired sequence was lift-and-shift first, Microsoft-native second.** Pivot.

No portal work was done during this session. No Azure resources were created. The Phase 1 state is unchanged. Only docs were written.

---

## Recent v2-azure branch commit log (for context)

The most recent commits to `v2-azure` reflect the spec/plan/amendment work that's now deferred:

```
acedd79  docs(SOC-AP): pivot — port v1 to Azure as new Phase 2; defer Microsoft-native rewrite to Phase 3
b418795  docs(v2-azure): amend Phase 2 plan to portal-only paths (no az CLI)
ee60b0e  docs(v2-azure): add Phase 2 implementation plan (21 tasks, portal-driven)
75a5207  docs(v2-azure): add Phase 2 SOAR Logic App design spec
4861acc  feat(v2-azure): complete Phase 1 — T1059.001 detection firing end-to-end
78c0b00  feat(v2-azure): migrate to Central US + provision Windows endpoint VM
f55b053  docs(v2-azure): add living architecture diagram (Mermaid)
af99d44  feat(v2-azure): scaffold branch with phase 1 spec and side-by-side architecture
```

Branch is **4 commits ahead of `origin/v2-azure`** as of the pivot commit (`acedd79`). Not pushed yet. User holds push authorization.
