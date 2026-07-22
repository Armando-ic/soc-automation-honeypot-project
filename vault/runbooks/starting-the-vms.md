---
status: active
updated: 2026-07-22
related: [[architecture/current-state]]
---

# Starting the VMs

Boot sequence for the SOC automation lab. **The lab moved to Azure IaaS at P2 (2026-05-26)** — the four VMs now live in resource group `rg-soc-v2-azure-central-us` (Central US), not local VMware. (The old local-VMware procedure with `192.168.129.x` IPs is retired; those VMs were decommissioned and archived to `F:\VMs\`.)

## Prerequisites

- Azure access to `rg-soc-v2-azure-central-us` (the portal, or `az login` for the CLI).
- The SSH key for the Linux VMs: `C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem`.
- **Auto-shutdown is 11 PM Eastern on all four VMs**, so they are usually stopped (deallocated) and must be started before use.

## VM start order (matters)

Start the SIEM first so forwarders/agents have somewhere to ship; the rest can start in parallel.

1. **`vm-soc-v2-splunk`** (`10.0.0.5`) — Splunk SIEM, start first
2. **`vm-soc-v2-n8n`** (`10.0.0.6`) — n8n SOAR engine
3. **`vm-soc-v2-iris`** (`10.0.0.7`) — DFIR-IRIS case management
4. **`vm-soc-v2-win`** (`10.0.0.4`) — Windows endpoint generating telemetry

**Start each VM:** Azure portal → the VM → **Start** (~30 s each to reach Running, parallelizable across all four). Or via the CLI:

```bash
az vm start -g rg-soc-v2-azure-central-us -n vm-soc-v2-splunk
az vm start -g rg-soc-v2-azure-central-us -n vm-soc-v2-n8n
az vm start -g rg-soc-v2-azure-central-us -n vm-soc-v2-iris
az vm start -g rg-soc-v2-azure-central-us -n vm-soc-v2-win
```

## After boot — getting things running

### Splunk (`vm-soc-v2-splunk`)

Auto-starts at boot (`Splunkd.service`, boot-start enabled). No manual start needed once the VM is Running.

### n8n (`vm-soc-v2-n8n`)

Not configured to auto-start the container. SSH in and bring the stack up (modern `docker compose` plugin, not legacy `docker-compose`):

```bash
ssh -i C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem azureuser@x.x.x.x
cd ~ && docker compose up -d
```

Web UI then available at http://x.x.x.x:5678 (or `http://10.0.0.6:5678` intra-VNet).

### DFIR-Iris (`vm-soc-v2-iris`)

Same pattern, from the `iris-web` directory (five containers come up in sequence):

```bash
ssh -i C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem azureuser@x.x.x.x
cd ~/iris-web && docker compose up -d
```

Web UI at https://x.x.x.x (accept the self-signed cert warning; or `https://10.0.0.7` intra-VNet).

### Windows endpoint (`vm-soc-v2-win`)

Nothing to start manually — Sysmon and the Splunk Universal Forwarder run as services and start with the VM. Just confirm it reached Running.

## Verification

Public web UIs are **NSG-restricted to the home IP** (`x.x.x.x`); from inside the VNet use the private IPs.

| Service | Public (home-IP-restricted) | Private (intra-VNet) |
|---|---|---|
| Splunk | http://x.x.x.x:8000 | http://10.0.0.5:8000 |
| n8n | http://x.x.x.x:5678 | http://10.0.0.6:5678 |
| DFIR-Iris | https://x.x.x.x (self-signed) | https://10.0.0.7 |
| Windows (RDP) | RDP to x.x.x.x | 10.0.0.4 |

Detailed operational commands (restart a single service, the gotcha catalog) are in [[subprojects/2026-05-23-azure-port/runbook]]. Credentials: see [[runbooks/secrets-management]].
