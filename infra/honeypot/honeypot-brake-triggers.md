# honeypot-brake trigger definitions (Task A8)

Reference doc for the two trip-signal feeders plus the "you know the moment it fell" alert.
This is a doc, not a deployment: the live Splunk saved-search and the `honeypot-flow-feeder`
n8n workflow get created hands-on in Part B. The queries below are the source of truth for
what gets typed in.

**Two feeders, one brake.** Per spec section 3.3 (`docs/superpowers/specs/2026-07-13-honeypot-opening-live-telemetry-design.md`),
the auto-brake has exactly one decision point: the `honeypot-brake` n8n workflow, listening on
`POST http://10.0.0.6:5678/webhook/honeypot-brake` (the `Brake Webhook` node, path `honeypot-brake`,
in `JSON/honeypot-brake.json` / `infra/honeypot/build_honeypot_brake_workflow.py`). Both triggers
below POST into that single webhook; the workflow's `Normalize Events` node reads whichever shape
shows up and forwards it to `grounding-service`'s `/brake/evaluate`. This is deliberate defense in
depth: the two triggers are independent (different data source, different latency, different
blind spot), so **losing either one still leaves a working brake**.

- **Host trigger (fast, blindable).** Sysmon EID 3 shipped by the Splunk UF, seconds of latency.
  An attacker who kills Sysmon or the UF blinds this one, but that kill is itself a captured,
  alertable signal, and it does nothing to the network trigger below.
- **Network trigger (much slower, authoritative).** Azure VNet flow logs via Traffic Analytics
  (`NTANetAnalytics`), **10-60 min latency** (TA's processing interval is 10 min, ingestion can
  take up to an hour). Enforced by the Azure control plane, outside the box entirely, so nothing
  running inside the honeypot can blind it. This is a backstop, not a fast brake: see section 2,
  and do not describe it as minutes-latent.

Both feeders emit the same output shape so `Normalize Events` treats them identically:

```json
{"events": [{"dst_ip": "<ip>", "dst_port": <port>}, ...], "source": "splunk" | "nsg"}
```

`source` is the only thing that tells the two triggers apart downstream (it's echoed back
by `/brake/evaluate` and shows up in the Discord "BRAKE FIRED" embed).

---

## 1. Host trigger: Splunk saved-search on Sysmon EID 3

**What it watches:** outbound network-connect events (Sysmon EventCode 3) from the honeypot,
over a trailing 5-minute window, grouped by destination. This is the raw material
`evaluate_egress` (`grounding-service/grounding_service/brake.py`) turns into a fan-out /
rate trip decision, so the search just needs to hand over the `dst_ip`/`dst_port` rows, not
do the trip math itself (the math is server-side, in the fails-closed `/brake/evaluate` call).

**Saved search (SPL):**

```spl
index=honeypot sourcetype=*Sysmon* EventCode=3 earliest=-5m
| stats count by DestinationIp, DestinationPort
| rename DestinationIp as dst_ip, DestinationPort as dst_port
```

> **OPEN GAP, be honest about this one.** The `AzurePublic` exclusion that section 2 introduces
> lives ONLY in the network feeder's KQL. The threshold it protects is enforced **server-side**:
> `evaluate_egress` counts every `dst_ip` on ports 80/443 that is not the Splunk host, with no
> destination classification whatsoever, and the SPL above ships all of them. So the 2026-07-15
> threshold calibration **does NOT cover this feeder**, which is the fast one that must not be
> lost. Worse, the exposure here is **unmeasured, not just undocumented**: the 20-distinct
> AzurePublic baseline was observed over 20-minute windows, and this search runs a 5-minute one,
> so whether a Windows Update burst clears `BRAKE_DISTINCT_DST_MAX=25` inside 5 minutes is simply
> unknown. Baseline it at the 5-minute window before B7, or the fast feeder may false-trip the
> brake on an idle box exactly the way the network feeder would have.

Schedule this to run every 1 minute over a 5-minute lookback (overlapping windows are fine;
`/brake/evaluate` is stateless per-call, it just looks at whatever rows it's handed).

**Alert action: webhook.** Splunk's alert-action webhook POSTs the search results as JSON.
Use a "Send as webhook" (or a small alert-script wrapper, since Splunk's raw webhook action
sends its own results envelope) that reshapes the result rows into the brake's expected body
before POSTing to `http://10.0.0.6:5678/webhook/honeypot-brake`:

```json
{
  "events": [
    {"dst_ip": "<DestinationIp>", "dst_port": <DestinationPort>}
  ],
  "source": "splunk"
}
```

One `{dst_ip, dst_port}` pair per result row (i.e. per distinct destination seen in the
window), `count` is informational only and not part of the shape the brake reads.

---

## 2. Network trigger: n8n PULL feeder over `NTANetAnalytics` (VNet flow logs)

> **Rewritten 2026-07-15 against the LIVE table.** The original design here (an Azure
> scheduled-query alert with an Action Group webhook POSTing `{events, source}` to the brake,
> reading `AzureNetworkAnalytics_CL`) was verified during Part B and is **dead four ways**. All
> four were confirmed against live data or Microsoft docs, none were theoretical:
>
> 1. **Wrong table.** VNet flow logs + Traffic Analytics write **`NTANetAnalytics`**;
>    `AzureNetworkAnalytics_CL` is the legacy NSG-flow-log table and **does not exist** in
>    `law-soc-v2-azure` (a live `union` returned `NTANetAnalytics` 18,333 rows and no such table).
>    Azure retired new NSG-flow-log creation, so the old table will never populate.
> 2. **Wrong column, and it fails silently.** `DestIp` is **empty for 100% of outbound public
>    flows** (live: 92/92 ExternalPublic and 106/106 AzurePublic on ports 80/443 from
>    `vm-honeypot-win`). The real addresses live bar-delimited inside space-separated
>    `DestPublicIps`. The old `project dst_ip = DestIP_s` would have returned zero rows forever.
>    (`DestIp` looks populated if you do NOT filter to outbound, because inbound brute-force
>    flows have `DestIp` = the honeypot's own address. That is the trap.)
> 3. **Action Groups cannot deliver this shape.** Log Alerts V2 (API 2021-08-01) embeds **no
>    search results**, only a `linkToSearchResultsAPI`, and Action Groups support **no custom
>    JSON body**. Azure's native payload has no `events` array, so `Normalize Events` would set
>    `events=[]`, `evaluate_egress([])` would not trip, and the feeder would be **silently
>    fail-OPEN**.
> 4. **Unreachable, and the workaround is unsafe.** Action Group webhooks fire from Microsoft's
>    public infrastructure and cannot reach private `10.0.0.6`. The only fix would be publicly
>    exposing the unauthenticated brake webhook, on an endpoint the honeypot's own attacker can
>    reach. Rejected.
>
> **Replacement: invert to PULL.** A separate n8n workflow (`honeypot-flow-feeder`): Schedule
> Trigger (10 min) -> query Log Analytics via the Azure Monitor Query API with a read-only SP ->
> reshape rows into the proven `{events, source:"nsg"}` contract -> POST to the existing
> `http://10.0.0.6:5678/webhook/honeypot-brake`. No inbound path, no public exposure, no Logic
> App, and the proven brake graph keeps a zero diff. Push buys no latency anyway: Traffic
> Analytics has a 10-minute processing interval, so this feeder is 10-60 min latent regardless.
> **The Splunk host trigger below is the FAST feeder; this one is the slow, control-plane
> backstop that cannot be blinded from inside the box.** Any claim of a fast network trip
> overstates it.

**What it watches:** the honeypot VM's outbound ALLOWED flows in VNet flow log data (Traffic
Analytics, table `NTANetAnalytics`), over a trailing 20-minute window. This is the
authoritative signal: it comes straight from the Azure control plane watching the wire, not
from anything running on the box, so it can't be blinded by killing a process inside the
honeypot.

**THRESHOLD CALIBRATION (live baseline, 2026-07-15, closed + idle honeypot).** Peak 20-minute
window was **20 distinct `AzurePublic` + 10 distinct `ExternalPublic` = ~30 distinct**, against
`BRAKE_DISTINCT_DST_MAX=25`. An idle box **would have false-tripped its own brake** (the 01:00
spike is Windows Update fanning out across CDN IPs). Hence `AzurePublic` is **excluded from the
fan-out count**: those are Microsoft's own service endpoints (Windows Update, IMDS, Falcon
cloud), not third parties, and this brake exists only to stop **third-party harm**. With
`AzurePublic` dropped, the observed `ExternalPublic` peak is **10 distinct**, leaving real
headroom under 25. Keep `MaliciousFlow` in scope: that is where scanning/DDoS would surface.

**Feeder query (KQL), verified against the live table:**

```kql
let lookback = 20m;   // >= 2x Traffic Analytics' 10-min processing interval, else batches drop
NTANetAnalytics
| where TimeGenerated > ago(lookback)      // ingestion time, NEVER FlowStartTime (late arrivals)
| where SubType == "FlowLog"
| where SrcVm == "rg-honeypot/vm-honeypot-win"   // NsgList is a placeholder under VNet flow logs
| where AllowedOutFlows > 0                      // outbound + allowed, enum-agnostic
| where DestPort in (80, 443)
| where FlowType in ("ExternalPublic", "MaliciousFlow")   // AzurePublic excluded, see below
// DestIp is ALWAYS empty for outbound public flows; the real addresses live bar-delimited
// inside space-separated DestPublicIps. Reading DestIp here returns nothing, forever.
| mv-expand d = split(DestPublicIps, " ") to typeof(string)
// distinct takes BARE column names only: no alias form, no expressions. Build both columns in
// extend first, or the query does not parse.
| extend dst_ip = tostring(split(d, "|")[0]), dst_port = DestPort
| where isnotempty(dst_ip)
| distinct dst_ip, dst_port
| take 5000
```

Every field above was confirmed against the live table on 2026-07-15 (`getschema` plus queries
that executed cleanly): `SubType`, `SrcVm`, `AllowedOutFlows`, `DestPort`, `FlowType`, `DestIp`,
`DestPublicIps`. Note what is deliberately NOT used: `NsgList` (a documented placeholder under
VNet flow logs, so it cannot scope), and `FlowDirection`/`FlowStatus` (Microsoft's docs
self-contradict on their values, `I`/`O`/`A`/`D` vs `Inbound`/`Outbound`/`Allowed`/`Denied`, so
direction is derived from the `AllowedOutFlows` counter instead, which is enum-agnostic).

Run the feeder on a 10-minute schedule with the 20-minute lookback above. The lookback must be
at least 2x Traffic Analytics' 10-minute processing interval or whole batches are dropped
between runs; the overlap is harmless because `/brake/evaluate` is stateless per call.

**Delivery: the feeder POSTs the brake's existing contract itself.** No Action Group, no Logic
App. The `honeypot-flow-feeder` workflow's Code node reshapes the rows and POSTs to
`http://10.0.0.6:5678/webhook/honeypot-brake`, `source` set to `"nsg"` instead of `"splunk"`:

```json
{
  "events": [
    {"dst_ip": "<dst_ip>", "dst_port": <dst_port>}
  ],
  "source": "nsg"
}
```

**Identity.** The feeder needs read access to `law-soc-v2-azure`, which `honeypot-brake-sp`
deliberately does NOT have (it is Network Contributor scoped to the single `nsg-honeypot`
resource). Use a SEPARATE read-only SP (`honeypot-flow-reader-sp`). Do not widen the brake SP:
merging them means one leaked secret grants NSG-write AND workspace-read, and couples the
safety-critical brake credential's rotation to a routine feeder. Honest limit: both secrets sit
in the same `.env` on the same box, so this defends against leak-of-one-value and allows
independent revocation, not against compromise of the box itself.

**Known fail-OPEN risk to alarm on.** `evaluate_egress` fails CLOSED on a non-list `events`
value but an EMPTY list does not trip. So a feeder that breaks and sends nothing (bad KQL, dead
SP secret, schema drift) is silently fail-OPEN: the brake simply never fires from this path.
The pull design at least makes this loud (a broken query shows up as a failed n8n execution in
seconds, whereas a broken alert rule fires never and says nothing), but the host trigger
remains the feeder that must not be lost.

---

## 3. "You know the moment it fell": successful RDP logon alert

**What it watches:** a successful interactive RDP logon (Security EventCode 4624, Logon_Type
10) on the honeypot. This is not a brake trigger, it's a heads-up: the instant the weak
credential actually gets used, someone should know, so the attended-monitoring half of the
safety posture (spec section 3, "semi-attended with an auto-brake") has something to watch for.

**Saved search (SPL):**

```spl
index=honeypot source=WinEventLog:Security EventCode=4624 Logon_Type=10 earliest=-5m
| table _time, src_ip, user
```

Schedule every 1 minute over a 5-minute lookback, fire-once-per-result (this should be a rare
event by design, so no dedup/throttling logic beyond Splunk's normal per-alert-fire behavior
is needed).

**Alert action: Discord webhook.** Straight to Discord, not through the brake webhook (this
alert doesn't feed `/brake/evaluate`, it's a standalone notification):

```
honeypot compromised: successful RDP logon from <src_ip> as <user>
```

with `<src_ip>` and `<user>` filled from the matching row (`src_ip`, `user`). This is the
"you know the moment it fell" signal called out in the design spec (section 4, prep step 5):
a human should never learn about a successful compromise secondhand, from the post-exploitation
telemetry showing up later. It fires the moment the logon succeeds.
