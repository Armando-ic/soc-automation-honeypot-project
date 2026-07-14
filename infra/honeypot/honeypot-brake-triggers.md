# honeypot-brake trigger definitions (Task A8)

Reference doc for the two trip-signal feeders plus the "you know the moment it fell" alert.
This is a doc, not a deployment: the live saved-searches / alert rules get created hands-on
in Part B. The queries below are the source of truth for what gets typed in.

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
- **Network trigger (slower, authoritative).** Azure NSG flow logs, minutes of latency. Enforced
  by the Azure control plane, outside the box entirely, so nothing running inside the honeypot
  can blind it.

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

## 2. Network trigger: Log Analytics scheduled-query alert on `AzureNetworkAnalytics_CL`

**What it watches:** the honeypot NIC's outbound ALLOWED flows in NSG flow log data (Traffic
Analytics, table `AzureNetworkAnalytics_CL`), over a trailing 5-minute window. This is the
authoritative signal: it comes straight from the Azure control plane watching the wire, not
from anything running on the box, so it can't be blinded by killing a process inside the
honeypot.

**Scheduled-query alert (KQL):**

```kql
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(5m)
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where NSGList_s has "nsg-honeypot"
| project dst_ip = DestIP_s, dst_port = toint(DestPort_d)
| summarize count() by dst_ip, dst_port
```

Filter fields (`FlowDirection_s`, `FlowStatus_s`, `NSGList_s`, `DestIP_s`, `DestPort_d`) are
the standard `AzureNetworkAnalytics_CL` / NSG-flow-log schema; confirm the exact honeypot NIC
identifier (NSG name or resource id substring) against the live table once flow logs are
enabled in Part B, per `nsg-rules.md`'s `nsg-honeypot`.

Run the alert rule on a 5-minute evaluation frequency over a 5-minute time window (matches the
host trigger's cadence so the two triggers see roughly the same slice of activity, just with
the network trigger arriving a few minutes later).

**Action Group: webhook.** The alert rule's Action Group fires a webhook POST to
`http://10.0.0.6:5678/webhook/honeypot-brake` with the same output shape, `source` set to
`"nsg"` instead of `"splunk"`:

```json
{
  "events": [
    {"dst_ip": "<dst_ip>", "dst_port": <dst_port>}
  ],
  "source": "nsg"
}
```

Azure Monitor's default Action Group webhook payload wraps the query results in its own
schema, so the Action Group needs a thin transform (Logic App or the webhook's custom payload
option) to reshape the KQL rows into `{events, source}` before it hits the brake webhook,
same idea as the Splunk alert-action wrapper above.

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
