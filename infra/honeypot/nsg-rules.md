# nsg-honeypot — security rules (Task 3, 2026-06-24)

NSG `nsg-honeypot` (`rg-honeypot`, Central US), associated to `vnet-honeypot/snet-honeypot`.
Config-as-docs for rebuild. All custom priorities are within Azure's valid range (100–4096).

## Inbound — the attack surface (what we WANT exposed)
| Prio | Name | Source | Dest | Dest port | Proto | Action |
|---|---|---|---|---|---|---|
| 1000 | allow-rdp-internet | Internet | Any | 3389 | TCP | Allow |
| 1010 | allow-smb-internet | Internet | Any | 445 | TCP | Allow |
| 1020 | allow-web-internet | Internet | Any | 80,443 | TCP | Allow |
| 65500 | DenyAllInBound (default) | Any | Any | Any | Any | Deny |

> **Destination MUST be `Any`** (not `Internet`): post-NAT the NSG sees the VM's *private* IP,
> which the `Internet` tag excludes — `Destination=Internet` silently fails to match → RDP/SMB
> blocked. The ⚠️ on `allow-rdp-internet` is Azure's expected "RDP exposed to internet" advisory —
> intended for a honeypot.

## Outbound — monitored-limited egress (Option A; first match wins)
| Prio | Name | Source | Destination | Dest port | Proto | Action |
|---|---|---|---|---|---|---|
| 1000 | allow-splunk-telemetry | Any | `20.236.193.253/32` | 9997 | TCP | Allow |
| 1010 | allow-dns | Any | Any | 53 | Any | Allow |
| 1020 | allow-web | Any | `Internet` (tag) | 80,443 | TCP | Allow |
| 4000 | deny-soc-private | Any | `10.0.0.0/8` | * | Any | Deny |
| 4096 | deny-all-other-egress | Any | Any | * | Any | Deny |

> - `allow-web` (80,443) covers the **CrowdStrike sensor** (HTTPS to `*.cloudsink.net`/Falcon API)
>   **and** captures C2/callback-over-HTTPS.
> - `allow-dns` Destination=`Any` (port 53 only) so Azure platform DNS `168.63.129.16` isn't blocked.
> - `deny-soc-private` blocks the SOC VNet incl. Splunk's private `10.0.0.5`.
> - `deny-all-other-egress` (`4096` = max NSG priority) overrides Azure's default
>   `AllowInternetOutBound` → once owned, the honeypot can reach **only** Splunk:9997, DNS, and
>   web:80/443 — no arbitrary-port egress (no reverse shells, mining pools, scanning).
> - Telemetry targets Splunk's **public** IP because the honeypot VNet is **un-peered** (Option A).
