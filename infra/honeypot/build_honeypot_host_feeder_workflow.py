"""Build an importable n8n workflow JSON for honeypot-host-feeder (Part B, session 40).

Generator/source-of-truth for JSON/honeypot-host-feeder.json. This is the brake's FAST feeder:

  Schedule Trigger(1m) -> host_feed (GET /brake/host-feed) -> post_brake (POST the contract)

WHY A PULL, NOT SPLUNK'S WEBHOOK ALERT ACTION. honeypot-brake-triggers.md section 1 documented a
Splunk saved-search with a webhook alert action POSTing {"events":[...], "source":"splunk"}. That
cannot work and was proven dead against the real app on 2026-07-15: Splunk's built-in webhook
envelope is FIXED to {result, sid, results_link, search_name, owner, app}, `result` is documented
as the FIRST result row only, and there is no `events` key under ANY trigger setting. POSTed
verbatim to /brake/evaluate it returned 200 trip:false -- a green, successfully-firing alert
feeding a brake that could never trip. So the fast feeder inverts to a pull, mirroring the network
feeder's design, and all the deterministic work (the SPL, the Splunk auth, the error/truncation
precedence) stays server-side in the pytest-tested /brake/host-feed route.

SEPARATE WORKFLOW ON PURPOSE: the proven brake graph keeps a zero diff, which is reason enough for
a graph that has been live-verified end to end. (Precision, since an earlier draft of this comment
overstated it: the b0a68b3 bug class is specifically a multi-output node whose branches CONVERGE on
a reader, NOT a second trigger. A second trigger would not reproduce it. Touching a proven safety
graph at all is simply a risk we decline.)

NO CODE NODE, AND NO onError OVERRIDES -- both deliberate:
  * post_brake reads $json (its immediate input), so there is no default-branch accessor to bind
    wrong. host_feed is single-output anyway; this is belt and braces against the b0a68b3 class.
  * n8n's DEFAULT onError is stopWorkflow, which is correct here. /brake/host-feed 503s whenever
    Splunk errors; halting means the execution goes RED and nothing is POSTed.
    What continueRegularOutput would ACTUALLY do (an earlier draft of this comment had it exactly
    backwards, in the dangerous direction): POST a body with events undefined -> JSON.stringify
    drops the key -> honeypot-brake's Normalize Events coerces the missing key to events:[] ->
    200 trip:false -> a GREEN, silently inert feeder. NOT a strangle. The decision stands and the
    reason is stronger than the one first written down: red-and-loud beats green-and-blind.

KNOWN AND OWED (a B7 gate, not a nice-to-have). A red execution is the ONLY signal that this feeder
is broken, and NOTHING SURFACES IT: this workflow sets no errorWorkflow, and 1440 green executions
a day will bury one red row in the list. A healthy quiet box and a dead feeder both produce zero
watched rows, and /brake/evaluate answers both identically ({"trip": false, "distinct_dst": 0}).
On the CLOSED, idle box, 24h of real telemetry produced ZERO rows on the watched ports (the
SwiftOnSecurity NetworkConnect include covers neither svchost.exe nor ports 80/443, so Windows
Update's CDN fan-out is invisible here even though the flow logs see it). So the healthy steady
state IS the indistinguishable one.

Two things that make the owed liveness work harder than it looks, both found in review:
  * A trip SEVERS this feeder's own input. The brake's deny rule goes in at priority 100 with
    protocol/port "*", and allow-splunk-telemetry sits at 1000 -- lowest number wins, so the trip
    kills the honeypot's 9997 forwarding too. After any legitimate trip, no new events reach
    Splunk, the trailing 5-minute window rolls past the last-shipped rows, and this feeder returns
    ok/0 rows -> 200 {"events": []} -> GREEN, permanently. So an "N-consecutive-empty" alarm would
    fire forever after every real trip and train the operator to ignore it. Liveness must be
    re-specified before it is built, and it belongs on the SOC side, which survives the severing.
  * There is no observe-only mode. BRAKE_ENABLED=false gates the NSG half only: /brake/nsg-deny
    returns HTTP 200 {"fired": false, "reason": "brake_not_configured"}, n8n reads 200 as success
    and walks on to the Falcon chain, and /falcon/contain-guard consults FALCON_PINNED_AID alone.
    Disabling both layers takes BOTH switches.

Secrets: none. This workflow has no credentials at all (grounding-service is unauthenticated on
soar-net; the brake webhook is unauthenticated on the private SOC network). Run from anywhere:
  python infra/honeypot/build_honeypot_host_feeder_workflow.py
"""
import json
import os

GS = "http://grounding-service:8000"                            # soar-net loopback, no auth
BRAKE_WEBHOOK = "http://10.0.0.6:5678/webhook/honeypot-brake"   # the proven brake (private)

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(_REPO_ROOT, "JSON", "honeypot-host-feeder.json")

# Canvas layout. Unlike honeypot-brake (where A10 made the y values load-bearing, because
# executionOrder v1 sorts a fan-out by canvas position), this chain is linear: there is no
# fan-out to order, so these are cosmetic.
POS = {
    "Schedule Trigger": [0, 0],
    "host_feed": [240, 0],
    "post_brake": [480, 0],
}


def node(name, ntype, tv, params, nid=None):
    return {"parameters": params, "id": nid or name.lower().replace(" ", "-"), "name": name,
            "type": ntype, "typeVersion": tv, "position": POS[name]}


nodes = [
    # 1-minute schedule against the SPL's trailing 5-minute window. The 5x overlap is deliberate
    # and harmless: /brake/evaluate is stateless per call, so re-sent connections cannot
    # accumulate into a false rate trip. It does mean one burst can trip up to 5 times; the NSG
    # PUT is idempotent (same rule name + priority) and contain is AID-pinned, so that is noise,
    # not damage. The overlap is also the gap guard: a missed tick is covered by the next four.
    node("Schedule Trigger", "n8n-nodes-base.scheduleTrigger", 1.2,
         {"rule": {"interval": [{"field": "minutes", "minutesInterval": 1}]}}),

    # GET, not POST: the endpoint is a read. It returns {events, source, outcome, row_count} on
    # outcome ok|capped_incomplete, and 503s on outcome=error so this node halts (see module doc).
    node("host_feed", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "GET", "url": f"{GS}/brake/host-feed", "options": {}}),

    # Forwards the endpoint's own {events, source} verbatim -- source is "splunk", set server-side,
    # and it is what tells /brake/evaluate which feeder spoke (it is echoed into the Discord embed).
    node("post_brake", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": BRAKE_WEBHOOK, "options": {}, "sendBody": True,
          "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ events: $json.events, source: $json.source }) }}"}),
]


def sticky(name, content, pos, w, h, color=7):
    return {"parameters": {"content": content, "height": h, "width": w, "color": color},
            "id": "sticky-" + name.lower().replace(" ", "-"),
            "name": name, "type": "n8n-nodes-base.stickyNote", "typeVersion": 1, "position": pos}


nodes += [
    sticky("Doc - How It Works",
           "## 🚦 honeypot-host-feeder\n**What it does:** every minute it asks grounding-service for the "
           "honeypot's recent Sysmon EID3 connections and hands them to the `honeypot-brake` webhook, which "
           "decides whether to slam the brake.\n\n**Why a pull:** Splunk's built-in webhook alert action "
           "physically cannot send this shape (fixed envelope, first result row only, no `events` key), so "
           "it would have fed the brake an empty list forever while looking perfectly healthy.",
           [-64, -300], 460, 180, 4),
    sticky("Doc - Failure Modes",
           "## ⚠️ If this workflow goes RED\n**That is the design.** `/brake/host-feed` returns 503 when "
           "Splunk errors, and these nodes deliberately halt rather than POST a malformed body (which would "
           "fail closed into an NSG egress-deny and strangle the box).\n\n**A red execution means the fast "
           "feeder is DOWN and the brake is running on the 10-60 min network backstop alone.** Fix it before "
           "the honeypot stays open.\n\n**Green but always empty is NOT proof of health** - a quiet box and a "
           "dead feeder look identical from here.",
           [432, -300], 460, 180, 3),
]

connections = {
    "Schedule Trigger": {"main": [[{"node": "host_feed", "type": "main", "index": 0}]]},
    "host_feed": {"main": [[{"node": "post_brake", "type": "main", "index": 0}]]},
    # post_brake is terminal: the brake workflow owns everything downstream of the webhook.
}

workflow = {
    "name": "honeypot-host-feeder",
    "nodes": nodes,
    "connections": connections,
    "active": False,
    "settings": {"executionOrder": "v1"},
    "meta": {"templateCredsSetupCompleted": False},
    "tags": [],
}

if __name__ == "__main__":
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(workflow, fh, indent=2, ensure_ascii=False)

    with open(OUT, encoding="utf-8") as fh:
        reparsed = json.load(fh)
    print("OK ->", OUT)
    print("nodes:", len(reparsed["nodes"]))
    print("node names:", [n["name"] for n in reparsed["nodes"]])
    print("connection keys:", list(reparsed["connections"].keys()))
