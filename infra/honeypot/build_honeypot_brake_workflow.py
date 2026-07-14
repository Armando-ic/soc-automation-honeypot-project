"""Build an importable n8n workflow JSON for honeypot-brake (Task A7): a fails-closed
auto-brake that wires trigger feeders through grounding-service /brake/evaluate and, on
a trip, fires both an Azure NSG egress-deny (/brake/nsg-deny) and the existing AID-pinned
falcon-contain path (resolve_host -> contain_guard -> contain), reused in the same shape
as build_falcon_contain_workflow.py so the AID pin, not the hostname, bounds the blast
radius of the contain action.

Design: Brake Webhook (/honeypot-brake) -> Normalize Events -> evaluate -> Trip?
  true  -> nsg_deny -> resolve_host -> contain_guard -(200)-> contain -> Build Brake Alert
                                                     \\-(409)-> Discord REFUSED (stop)
           Build Brake Alert -> Discord BRAKE FIRED
  false -> No-op end

contain_guard mirrors the falcon-contain generator exactly: onError continueErrorOutput,
output 0 (success, resolved AID) feeds contain, output 1 (409, not exactly one pinned
device) feeds a REFUSED notice and stops -- contain never fires off the raw hostname.

Secrets stay placeholders (REPLACE_ME cred id + Discord URL) -> re-bind on import.
Run from anywhere:  python infra/honeypot/build_honeypot_brake_workflow.py
"""
import json
import os

GS = "http://grounding-service:8000"
US2 = "https://api.us-2.crowdstrike.com"
DISCORD = "https://discord.com/api/webhooks/REPLACE_ME"
CRED_FALCON = {"crowdStrikeOAuth2Api": {"id": "REPLACE_ME", "name": "Crowdstrike Falcon Account"}}
HOST = "vm-honeypot-win"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "JSON", "honeypot-brake.json")


def node(name, ntype, tv, params, pos, nid=None, creds=None, extra=None):
    n = {"parameters": params, "id": nid or name.lower().replace(" ", "-"), "name": name,
         "type": ntype, "typeVersion": tv, "position": POS.get(name, pos)}
    if creds:
        n["credentials"] = creds
    if extra:
        n.update(extra)
    return n


def falcon_http(name, method, url, pos, json_body=None, send_query=None, extra=None):
    params = {"method": method, "url": url, "authentication": "predefinedCredentialType",
              "nodeCredentialType": "crowdStrikeOAuth2Api", "options": {}}
    if send_query is not None:
        params.update({"sendQuery": True, "queryParameters": {"parameters": send_query}})
    if json_body is not None:
        params.update({"sendBody": True, "specifyBody": "json", "jsonBody": json_body})
    return node(name, "n8n-nodes-base.httpRequest", 4.4, params, pos, creds=CRED_FALCON, extra=extra)


def discord(name, body, pos, nid=None):
    return node(name, "n8n-nodes-base.httpRequest", 4.4,
                {"method": "POST", "url": DISCORD, "sendBody": True, "specifyBody": "json",
                 "jsonBody": body, "options": {}}, pos, nid=nid)


POS = {
    "Brake Webhook": [0, 0],
    "Normalize Events": [220, 0],
    "evaluate": [440, 0],
    "Trip?": [660, 0],
    "No-op end": [880, 200],
    "nsg_deny": [880, 0],
    "resolve_host": [1100, 0],
    "contain_guard": [1320, 0],
    "Discord REFUSED": [1320, 220],
    "contain": [1540, 0],
    "Build Brake Alert": [1760, 0],
    "Discord BRAKE FIRED": [1980, 0],
}

JS_NORMALIZE = r"""// Map the feeder payload into the /brake/evaluate request shape. The two
// feeders (Splunk high-fan-out-egress + Splunk non-9997-egress saved searches)
// POST a webhook body carrying `events` (the raw result rows) and a `source`
// tag identifying which feeder fired; pass events through untouched and
// default source to 'unknown' if the feeder omitted it.
const body = $input.first().json.body || $input.first().json || {};
const events = Array.isArray(body.events) ? body.events : [];
const source = body.source || 'unknown';
return [{ json: { events, source } }];"""

REFUSED_BODY = ("={{ JSON.stringify({ embeds: [{ "
                "title: '⛔ Brake contain REFUSED - " + HOST + "', "
                "description: 'contain-guard returned 409: the hostname did not resolve to exactly one "
                "device whose AID == the pinned honeypot AID. No contain was attempted (the NSG egress-deny "
                "may still be in effect).', "
                "color: 15158332 }] }) }}")

JS_BUILD_FIRED = r"""// Assemble the Discord BRAKE FIRED embed from the evaluate/nsg_deny/contain reads.
const ev = $('evaluate').first().json || {};
const nsg = $('nsg_deny').first().json || {};
const desc = 'reason: **' + (ev.reason || 'unknown') + '**\n'
  + 'distinct_dst: ' + (ev.distinct_dst ?? 'n/a') + ', conn_count: ' + (ev.conn_count ?? 'n/a')
  + ', source: ' + (ev.source || 'unknown') + '\n\n'
  + 'NSG access: **' + (nsg.access || 'unknown') + '** (' + (nsg.provisioning_state || 'unknown') + ')\n'
  + 'Falcon contain: **action submitted** (AID-pinned; confirm in the Falcon console or via the '
  + 'falcon-contain workflow). NSG egress-deny above is the authoritative brake.';
const discord_body = { embeds: [{ title: '🛑 AUTO-BRAKE FIRED - ' + '""" + HOST + r"""',
  description: desc, color: 15548997 }] };
return [{ json: { discord_body } }];"""

nodes = [
    node("Brake Webhook", "n8n-nodes-base.webhook", 2.1,
         {"httpMethod": "POST", "path": "honeypot-brake", "options": {}},
         [0, 0], extra={"webhookId": "honeypot-brake"}),

    node("Normalize Events", "n8n-nodes-base.code", 2,
         {"jsCode": JS_NORMALIZE}, POS["Normalize Events"]),

    node("evaluate", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": f"{GS}/brake/evaluate", "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ events: $json.events, source: $json.source }) }}",
          "options": {}}, POS["evaluate"]),

    node("Trip?", "n8n-nodes-base.if", 2.2,
         {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose", "version": 2},
                         "conditions": [{"id": "trip", "leftValue": "={{ $json.trip }}",
                                         "rightValue": "", "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
                         "combinator": "and"},
          "options": {}}, POS["Trip?"]),

    node("No-op end", "n8n-nodes-base.noOp", 1, {}, POS["No-op end"]),

    node("nsg_deny", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": f"{GS}/brake/nsg-deny", "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({}) }}", "options": {}}, POS["nsg_deny"]),

    falcon_http("resolve_host", "GET", f"{US2}/devices/queries/devices/v1", POS["resolve_host"],
                send_query=[{"name": "filter", "value": f"hostname:'{HOST}'"}]),

    node("contain_guard", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": f"{GS}/falcon/contain-guard", "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ resolved_ids: $('resolve_host').item.json.resources || [] }) }}",
          "options": {}}, POS["contain_guard"], extra={"onError": "continueErrorOutput"}),

    discord("Discord REFUSED", REFUSED_BODY, POS["Discord REFUSED"]),

    falcon_http("contain", "POST", f"{US2}/devices/entities/devices-actions/v2?action_name=contain",
                POS["contain"], json_body="={{ JSON.stringify({ ids: [$('contain_guard').item.json.aid] }) }}"),

    node("Build Brake Alert", "n8n-nodes-base.code", 2,
         {"jsCode": JS_BUILD_FIRED}, POS["Build Brake Alert"]),

    discord("Discord BRAKE FIRED", "={{ JSON.stringify($json.discord_body) }}", POS["Discord BRAKE FIRED"]),
]

connections = {
    "Brake Webhook": {"main": [[{"node": "Normalize Events", "type": "main", "index": 0}]]},
    "Normalize Events": {"main": [[{"node": "evaluate", "type": "main", "index": 0}]]},
    "evaluate": {"main": [[{"node": "Trip?", "type": "main", "index": 0}]]},
    "Trip?": {"main": [
        [{"node": "nsg_deny", "type": "main", "index": 0}],       # output 0: true -> fire the brake
        [{"node": "No-op end", "type": "main", "index": 0}],      # output 1: false -> no trip, stop
    ]},
    "nsg_deny": {"main": [[{"node": "resolve_host", "type": "main", "index": 0}]]},
    "resolve_host": {"main": [[{"node": "contain_guard", "type": "main", "index": 0}]]},
    "contain_guard": {"main": [
        [{"node": "contain", "type": "main", "index": 0}],            # output 0: success (aid)
        [{"node": "Discord REFUSED", "type": "main", "index": 0}],    # output 1: 409 error -> refused + stop
    ]},
    "contain": {"main": [[{"node": "Build Brake Alert", "type": "main", "index": 0}]]},
    "Build Brake Alert": {"main": [[{"node": "Discord BRAKE FIRED", "type": "main", "index": 0}]]},
}

workflow = {
    "name": "honeypot-brake",
    "nodes": nodes,
    "connections": connections,
    "active": False,
    "settings": {"executionOrder": "v1"},
    "meta": {"templateCredsSetupCompleted": False},
    "tags": [],
}

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(workflow, fh, indent=2, ensure_ascii=False)

with open(OUT, encoding="utf-8") as fh:
    reparsed = json.load(fh)
print("OK ->", OUT)
print("nodes:", len(reparsed["nodes"]))
print("node names:", [n["name"] for n in reparsed["nodes"]])
