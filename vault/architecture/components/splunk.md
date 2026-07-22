---
status: active
updated: 2026-05-26
related: [[architecture/current-state]], [[architecture/components/splunk-mcp]], [[architecture/components/sysmon]], [[subprojects/2026-05-23-azure-port/runbook]]
---

# Splunk

## What it is

The SIEM. Splunk Enterprise running on Ubuntu Server. **As of P2 (2026-05-26) running on Azure IaaS** (`vm-soc-v2-splunk` in `rg-soc-v2-azure-central-us`); the local-VMware host (`MyDFIR-Splunk`, 192.168.129.131) was decommissioned during P2 Task 20 and archived to `F:\VMs\MyDFIR-Splunk\`.

## Configuration (P2 / Azure)

| | |
|---|---|
| Host | `vm-soc-v2-splunk` (Azure VM, Central US, `Standard_D4s_v3`) |
| Public Web UI | http://x.x.x.x:8000 (NSG-restricted to home IP) |
| Private receiver | 10.0.0.5:9997 (intra-VNet for Sysmon UF traffic) |
| Management API | https://10.0.0.5:8089 (internal; not exposed) |
| Version | Splunk Enterprise **10.4.0** (build `f798d4d49089`) |
| License | **Splunk Developer Personal License** — 10 GB/day, expires 2026-11-19 |
| Index for project data | `mydfir-project` |
| Admin user | `mydfir` (password in gitignored secrets file) |
| Service | `Splunkd.service` (systemd; boot-start enabled) |
| Auto-shutdown | 11 PM Eastern |

See [[subprojects/2026-05-23-azure-port/runbook]] for operational commands and gotcha catalog.

## Migrated from v1 (decommissioned 2026-05-23 → 2026-05-26)

Original local Splunk on `MyDFIR-Splunk` (192.168.129.131) was decommissioned during P2 Task 20. Configuration was fresh-installed in Azure rather than VHD-imported (rationale: Trial-clock reset, no historical-index migration cost). VMDK archive lives at `F:\VMs\MyDFIR-Splunk\`. Sysmon UF on `vm-soc-v2-win` was re-pointed to the new indexer at Task 12; ATH/synthetic events from the Windows endpoint now land in this Azure Splunk.

## Apps installed

- **Splunk Add-on for Microsoft Windows** (`Splunk_TA_windows`, v10.0.1) — general Windows Event Log channel parsing; sets `sourcetype=XmlWinEventLog` for the Security/App/System/Sysmon channels.
- **Splunk Add-on for Microsoft Sysmon** (`Splunk_TA_microsoft_sysmon`, v5.0.0) — Sysmon-specific field extractions; props/transforms keyed on `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. Installed during D1 (2026-04-30).

## Saved searches / alerts

| Name | Status | Cron | Trigger | Webhook target | Notes |
|---|---|---|---|---|---|
| `Test-Brute-Force-External-Spoofed` | disabled | `* * * * *` (test value) | For each result | n/a | A1/A2 development; disabled at A2 closeout 2026-04-30. SPL re-derived during P2 Task 11 (canonical not in vault); reconstruction-only. |
| `T1059.001 - PowerShell Encoded Command` | enabled | `*/5 * * * *` | For each result | `http://10.0.0.6:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` | D1 worked-example detection. See [[../../detections/t1059-001-powershell-encoded]]. |
| `T1059.003 - Suspicious cmd.exe IOC References` | enabled | `*/5 * * * *` | For each result | same n8n webhook URL | Created 2026-05-19 (demo session); back-ported to Azure Splunk 2026-05-26 during P2 Task 24 IOC validation fire. Exercises AbuseIPDB + VirusTotal naturally. SPL captured at [[subprojects/2026-05-23-azure-port/notes]] Task 24 prep. |

The brute-force search will be replaced with a properly-thresholded version as part of future detection-engineering work; tracking is captured in [[../../subprojects/2026-04-30-detection-foundations/notes]].

## Sysmon ingestion (D1)

Sysmon events from the Azure Windows VM (`vm-soc-v2-win`, `10.0.0.4`; replaces the decommissioned local Win10 `DESKTOP-VNEF7PC` at 192.168.129.130) land in the `mydfir-project` index alongside Windows Security/App/System events under `sourcetype=XmlWinEventLog`. **Differentiate by `source=`, not `sourcetype=`:**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

The `XmlWinEventLog:` prefix (not `WinEventLog:`) is the canonical Sysmon source value when the Splunk Add-on for Microsoft Sysmon is installed; that add-on's parsing is keyed on this exact source.

See [[architecture/components/sysmon]] for the full EventCode + field reference, install metadata (commit SHA, version, hashes), and gotchas (e.g., `host` field instead of `ComputerName`, the `realtime_schedule=False` saved-search requirement).

### Side-effects of D1's UF restart on the PowerShell + Defender source values

The pre-existing UF `inputs.conf` had `source =` overrides on the `Microsoft-Windows-PowerShell/Operational` and `Microsoft-Windows-Windows Defender/Operational` stanzas that hadn't taken effect (forwarder hadn't restarted since 2026-04-25). D1's Phase 2 forwarder restart activated them. Their `source` values in Splunk are now **without** the `WinEventLog:` prefix:

- PowerShell channel: `source="Microsoft-Windows-PowerShell/Operational"` (was `"WinEventLog:Microsoft-Windows-PowerShell/Operational"`)
- Defender channel: `source="Microsoft-Windows-Windows Defender/Operational"` (was `"WinEventLog:Microsoft-Windows-Windows Defender/Operational"`)

Vault grep at the time confirmed no downstream consumers of the old strings. Future searches/dashboards against these channels should use the new (no-prefix) form.

## How to access

- Web UI: browser to http://x.x.x.x:8000 (NSG-restricted to home IP per [[subprojects/2026-05-23-azure-port/runbook]])
- SSH: `ssh -i C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem azureuser@x.x.x.x`
- MCP (programmatic): see [[architecture/components/splunk-mcp]] (note: MCP host references need update if the splunk-mcp doc still points at 192.168.129.131)
