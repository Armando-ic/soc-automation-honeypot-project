"""Build an importable n8n workflow JSON for honeypot-brake (Task A7): a fails-closed
auto-brake that wires trigger feeders through grounding-service /brake/evaluate and, on
a trip, fires both an Azure NSG egress-deny (/brake/nsg-deny) and the existing AID-pinned
falcon-contain path (resolve_host -> contain_guard -> contain), reused in the same shape
as build_falcon_contain_workflow.py so the AID pin, not the hostname, bounds the blast
radius of the contain action.

Design: Brake Webhook (/honeypot-brake) -> Normalize Events -> evaluate -> Trip?
  true  -> nsg_deny -+-> Build Brake Alert -> Discord BRAKE FIRED   (notify first, always)
                     \\-> resolve_host -> contain_guard -(200)-> contain   (best-effort)
                                                        \\-(409)-> Discord REFUSED (stop)
  false -> No-op end
  evaluate error output -> nsg_deny  (FAIL CLOSED: uncertainty fires the brake)

contain_guard mirrors the falcon-contain generator exactly: onError continueErrorOutput,
output 0 (success, resolved AID) feeds contain, output 1 (409, not exactly one pinned
device) feeds a REFUSED notice and stops -- contain never fires off the raw hostname.

A10 (2026-07-15), driven by a live dry-run: the alert hangs off nsg_deny, NOT off the end of
the Falcon chain, and every node on the fire path is non-halting. Before this, the brake
would flip the NSG and contain the box while Discord stayed silent if anything on the Falcon
chain threw -- and that had a date on it, since the Falcon trial lapses 2026-07-28, after
which auth failures would have made silent-brake the DEFAULT. A braked box with a sleeping
operator is the one outcome this workflow may never produce.

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


def discord(name, body, pos, nid=None, extra=None):
    return node(name, "n8n-nodes-base.httpRequest", 4.4,
                {"method": "POST", "url": DISCORD, "sendBody": True, "specifyBody": "json",
                 "jsonBody": body, "options": {}}, pos, nid=nid, extra=extra)


POS = {
    "Brake Webhook": [0, 0],
    "Normalize Events": [220, 0],
    "evaluate": [440, 0],
    "Trip?": [660, 0],
    "No-op end": [880, 200],
    "nsg_deny": [880, 0],
    # A10: the alert branch hangs straight off nsg_deny and runs ABOVE the Falcon chain,
    # deliberately independent of it. These y values are LOAD-BEARING, not cosmetic:
    # executionOrder v1 sorts a fan-out top-left-first by canvas position, so y=-200 (vs
    # resolve_host at y=0) is what makes the alert render before Falcon is even attempted.
    # A test pins Build Brake Alert y < resolve_host y.
    "Build Brake Alert": [1100, -200],
    "Discord BRAKE FIRED": [1320, -200],
    "resolve_host": [1100, 0],
    "contain_guard": [1320, 0],
    "Discord REFUSED": [1320, 220],
    "contain": [1540, 0],
}

JS_NORMALIZE = r"""// Two feeders converge here: the Splunk Sysmon-EID-3 host trigger and the
// Azure NSG-flow-log network trigger, each POSTing {events:[{dst_ip,dst_port}], source}.
// Losing either still leaves a working brake. Pass events through untouched and
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

JS_BUILD_FIRED = r"""// Assemble the Discord BRAKE FIRED embed. This node is the ONLY thing standing between a
// fired brake and a silently contained box, so it must NEVER throw.
//
// LIVE BUG (2026-07-15, n8n 2.21.7): the old line 2 was a bare
//   const ev = $('evaluate').first().json || {};
// and it threw "Cannot read properties of undefined (reading 'json')" on a REAL trip,
// killing Discord BRAKE FIRED after the NSG had already flipped to Deny.
// Cause: a zero-arg $('x').first() does NOT default to output 0. n8n resolves the default
// branchIndex by walking backwards from THIS node to 'evaluate' and taking the sourceIndex
// of the first connection it finds. Commit b0a68b3 gave evaluate a second (error) output
// that REJOINS the success path at nsg_deny, so that walk finds evaluate at index 1 -- the
// ERROR branch -- which is EMPTY on every successful trip. first() -> undefined -> .json
// -> TypeError, and the `|| {}` never ran because .json derefs first. Inverted polarity:
// the alert only survived when evaluate ERRORED, i.e. the path with nothing real to report.
// The trigger is the MERGE, not onError by itself: contain_guard is also two-output but its
// error branch dead-ends at Discord REFUSED, so it resolves to 0 and is safe.
// Fix: pass the branch index EXPLICITLY, probe every plausible accessor/branch, and degrade
// to a well-typed empty (the same pattern as Build Opus Input in honeypot-triage).
function readJson(name, branches) {
  for (const b of branches) {
    const tries = [() => $(name).first(b), () => ($(name).all(b) || [])[0]];
    for (const get of tries) {
      try {
        const it = get();
        if (it && it.json && typeof it.json === 'object') return it.json;
      } catch (e) { /* branch empty/absent, node never executed, or accessor unsupported */ }
    }
  }
  return {};
}

let desc;
try {
  // evaluate output 0 = the verdict {trip, reason, distinct_dst, conn_count, source}.
  // output 1 = n8n's error item on the fail-closed path, which has none of those fields.
  const ev = readJson('evaluate', [0]);
  const nsg = readJson('nsg_deny', [0, 1]);
  const haveVerdict = (typeof ev.trip !== 'undefined') || !!ev.reason;

  const why = haveVerdict
    ? 'reason: **' + (ev.reason || 'unknown') + '**\n'
      + 'distinct_dst: ' + (ev.distinct_dst ?? 'n/a') + ', conn_count: ' + (ev.conn_count ?? 'n/a')
      + ', source: ' + (ev.source || 'unknown')
    : 'reason: **no verdict from /brake/evaluate** (FAIL-CLOSED: the brake fired because '
      + 'evaluate errored or was unreadable, not because a threshold tripped)';

  // /brake/nsg-deny answers 200 with {fired:false} on brake_not_configured and brake_error,
  // so read `fired` -- inferring success from `access` would render a FAILED authoritative
  // brake as a mild 'unknown'. NB: nsg.reason is a FAILURE reason, not the same field as
  // ev.reason above.
  const nsgLine = (nsg.fired === true)
    ? 'NSG egress-deny: **fired** - access **' + (nsg.access || 'unknown') + '** ('
      + (nsg.provisioning_state || 'unknown') + ')'
    : 'NSG egress-deny: **NOT CONFIRMED** (' + (nsg.reason || 'unreadable') + '). The '
      + 'authoritative brake did not report success - check the NSG in the Azure portal NOW.';

  // A10: this node now fires on a branch PARALLEL to the Falcon chain, so at render time
  // contain has not run yet. Claiming "action submitted" here would be a lie. Say plainly
  // that the alert does not wait, and point at the console.
  desc = why + '\n\n' + nsgLine + '\n'
    + 'Falcon contain: AID-pinned, runs on a parallel branch. This alert **does not wait** on '
    + 'it and the contain response never confirms status anyway, so verify in the Falcon '
    + 'console. NSG egress-deny above is the authoritative brake.';
} catch (e) {
  // Last resort. A fired brake with no notification is the one outcome this workflow may
  // never produce, so alert with whatever we have rather than throwing.
  desc = 'AUTO-BRAKE FIRED, but building the alert detail failed ('
    + ((e && e.message) ? e.message : String(e))
    + '). Check the NSG deny rule and the Falcon console manually, NOW.';
}
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
          "options": {}}, POS["evaluate"], extra={"onError": "continueErrorOutput"}),

    node("Trip?", "n8n-nodes-base.if", 2.2,
         {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose", "version": 2},
                         "conditions": [{"id": "trip", "leftValue": "={{ $json.trip }}",
                                         "rightValue": "", "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
                         "combinator": "and"},
          "options": {}}, POS["Trip?"]),

    node("No-op end", "n8n-nodes-base.noOp", 1, {}, POS["No-op end"]),

    # A10: continueRegularOutput, NOT continueErrorOutput. A second output that rejoined the
    # alert's ancestry is exactly the convergence trap that caused the 2026-07-15 live bug.
    # One output means an nsg_deny failure still reaches the alert, which renders NOT CONFIRMED
    # rather than going silent.
    node("nsg_deny", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": f"{GS}/brake/nsg-deny", "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({}) }}", "options": {}}, POS["nsg_deny"],
         extra={"onError": "continueRegularOutput"}),

    # A10: non-halting. Default onError is stopWorkflow, so once the Falcon trial lapses
    # (2026-07-28) an auth failure here would halt the run AFTER the NSG already flipped and
    # take the sibling alert branch down with it.
    falcon_http("resolve_host", "GET", f"{US2}/devices/queries/devices/v1", POS["resolve_host"],
                send_query=[{"name": "filter", "value": f"hostname:'{HOST}'"}],
                extra={"onError": "continueRegularOutput"}),

    node("contain_guard", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": f"{GS}/falcon/contain-guard", "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ resolved_ids: $('resolve_host').item.json.resources || [] }) }}",
          "options": {}}, POS["contain_guard"], extra={"onError": "continueErrorOutput"}),

    discord("Discord REFUSED", REFUSED_BODY, POS["Discord REFUSED"]),

    # A10: terminal + non-halting. Nothing hangs off contain any more (the alert moved off this
    # chain), so a Falcon failure here costs the contain attempt and nothing else.
    falcon_http("contain", "POST", f"{US2}/devices/entities/devices-actions/v2?action_name=contain",
                POS["contain"], json_body="={{ JSON.stringify({ ids: [$('contain_guard').item.json.aid] }) }}",
                extra={"onError": "continueRegularOutput"}),

    # Non-halting is belt-and-braces here (the JS try/catch plus an unconditional return make a
    # throw all but impossible), but v1 runs this node BEFORE the Falcon chain, so on the freak
    # path where it did throw, halting would cost the contain too.
    node("Build Brake Alert", "n8n-nodes-base.code", 2,
         {"jsCode": JS_BUILD_FIRED}, POS["Build Brake Alert"],
         extra={"onError": "continueRegularOutput"}),

    # A10 review catch: v1 is depth-first, so this node runs BEFORE resolve_host/contain. With
    # the default onError=stopWorkflow a rate-limited Discord (429) would halt the run and the
    # box would never get contained -- A10 would have traded "Falcon failure kills the alert"
    # for "alert failure kills the contain". Discord is terminal, so continuing costs nothing.
    # retryOnFail because this is the last unretried link in the must-be-sent chain.
    discord("Discord BRAKE FIRED", "={{ JSON.stringify($json.discord_body) }}",
            POS["Discord BRAKE FIRED"],
            extra={"onError": "continueRegularOutput", "retryOnFail": True, "maxTries": 3}),
]

connections = {
    "Brake Webhook": {"main": [[{"node": "Normalize Events", "type": "main", "index": 0}]]},
    "Normalize Events": {"main": [[{"node": "evaluate", "type": "main", "index": 0}]]},
    "evaluate": {"main": [
        [{"node": "Trip?", "type": "main", "index": 0}],       # output 0: success -> normal trip check
        [{"node": "nsg_deny", "type": "main", "index": 0}],    # output 1: evaluate errored -> FAIL CLOSED, fire the brake
    ]},
    "Trip?": {"main": [
        [{"node": "nsg_deny", "type": "main", "index": 0}],       # output 0: true -> fire the brake
        [{"node": "No-op end", "type": "main", "index": 0}],      # output 1: false -> no trip, stop
    ]},
    # A10: the alert hangs off the AUTHORITATIVE brake, not off the end of the Falcon chain, so
    # no Falcon failure can swallow the notification.
    # ORDERING, stated accurately (an earlier comment here claimed list order and was WRONG):
    # executionOrder v1 does NOT use this list's order. workflow-execute.ts:2072-2085 re-sorts a
    # fan-out by CANVAS POSITION ("Always execute the node that is more to the top-left first"),
    # and list order only breaks ties on identical [x,y]. The alert runs first because POS puts
    # it at y=-200, ABOVE resolve_host at y=0. Keep it listed first too, for the tie case.
    # Delivery does NOT depend on this ordering (every node on the path is non-halting); the
    # layout only decides latency-to-notify. A test pins the y invariant, so do not "tidy" the
    # canvas by dragging the alert below the Falcon chain.
    "nsg_deny": {"main": [[
        {"node": "Build Brake Alert", "type": "main", "index": 0},    # notify first, always
        {"node": "resolve_host", "type": "main", "index": 0},         # then best-effort Falcon contain
    ]]},
    "resolve_host": {"main": [[{"node": "contain_guard", "type": "main", "index": 0}]]},
    "contain_guard": {"main": [
        [{"node": "contain", "type": "main", "index": 0}],            # output 0: success (aid)
        [{"node": "Discord REFUSED", "type": "main", "index": 0}],    # output 1: 409 error -> refused + stop
    ]},
    # contain is terminal now. Its result is deliberately NOT reported by the alert: the action
    # response never confirms containment anyway, so waiting on it bought nothing and cost the
    # notification.
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
