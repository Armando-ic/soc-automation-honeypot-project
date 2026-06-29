"""Build an importable n8n workflow JSON for falcon-alert-poller (Phase 0D-2, poll branch only).

Generator/source-of-truth for JSON/falcon-alert-poller.json. The WATCHDOG branch (C.10) and the
human-fired falcon-contain (Section D) are intentionally OMITTED — the watchdog was deferred
(racy auto-lifter, low marginal value, can't run during the 23:00-ET n8n shutdown anyway; see
the 0D-2 adversarial review + HANDOFF). This file emits ONLY the poll branch C.1-C.9:

  Schedule Trigger(15m) -> get_state -> falcon_query -> falcon_plan -> IF has_new
                                                                         (true) -> falcon_hydrate
                                                                                   -> falcon_map
                                                                                   -> Post+Collect
                                                                                   -> falcon_advance
                                                                         (false) -> end

Field names + the falcon_query FQL are the ones CONFIRMED live on us-2 (falcon-alerts-field-map.md):
host-scope was DROPPED (n8n 2.21.7 can't transmit the FQL '+' AND; tenant is honeypot-only, Contain
is AID-pinned), so the filter is `created_timestamp` alone — proven total:1 on the EICAR detection.

All deterministic logic lives in the grounding-service /falcon/* routes (pytest-tested); these nodes
are pure orchestration. Secrets stay placeholders (REPLACE_ME cred id) -> re-bind the CrowdStrike
OAuth2 credential on import. Run from anywhere:  python infra/honeypot/build_falcon_poller_workflow.py
"""
import json
import os

# CrowdStrike OAuth2 API credential (n8n built-in type). id is a placeholder -> re-bind on import.
# URL on the credential MUST be https://api.us-2.crowdstrike.com (our cloud); it mints the bearer.
CRED_FALCON = {"crowdStrikeOAuth2Api": {"id": "REPLACE_ME", "name": "Crowdstrike Falcon Account"}}

GS = "http://grounding-service:8000"                 # grounding-service over soar-net loopback (no auth)
US2 = "https://api.us-2.crowdstrike.com"             # Falcon us-2 (OAuth2 predefined cred injects bearer)
TRIAGE_WEBHOOK = "http://10.0.0.6:5678/webhook/honeypot-triage"   # existing honeypot-triage (private)

# ---- Post+Collect Code node (raw string preserves backticks). .first() not .item: this node runs
#      "Run Once for All Items" (no current item to pair .item to); the whole chain is single-item. ----
JS_POST_COLLECT = r"""// Post each Falcon-mapped alert to the existing honeypot-triage webhook, oldest-first,
// collecting ack results. Stops at the first failure so a partial failure never double-triages a
// later alert; grounding-service advance_state then honors only the contiguous-ok prefix (no SKIP).
// .first() (not .item): "Run Once for All Items" has no current item for .item to pair to.
const items = $('falcon_map').first().json.items || [];
const results = [];
for (const it of items) {
  let ok = false;
  try {
    await this.helpers.httpRequest({
      method: 'POST',
      url: 'http://10.0.0.6:5678/webhook/honeypot-triage',
      body: it.body,
      json: true,
    });
    ok = true;
  } catch (e) {
    ok = false;
  }
  results.push({ composite_id: it.composite_id, created: it.created, ok });
  if (!ok) break;                       // contiguous prefix only — un-acked tail retries next tick
}
return [{ json: { results } }];"""


def node(name, ntype, tv, params, pos, nid=None, creds=None, extra=None):
    n = {"parameters": params, "id": nid or name.lower().replace(" ", "-"), "name": name,
         "type": ntype, "typeVersion": tv, "position": pos}
    if creds:
        n["credentials"] = creds
    if extra:
        n.update(extra)
    return n


def http_gs(name, method, path, pos, json_body=None):
    """A grounding-service httpRequest node (no auth)."""
    params = {"method": method, "url": f"{GS}{path}", "options": {}}
    if json_body is not None:
        params.update({"sendBody": True, "specifyBody": "json", "jsonBody": json_body})
    return node(name, "n8n-nodes-base.httpRequest", 4.4, params, pos)


def http_falcon(name, method, url, pos, json_body=None, send_query=None):
    """A Falcon us-2 httpRequest node (CrowdStrike OAuth2 predefined credential)."""
    params = {"method": method, "url": url,
              "authentication": "predefinedCredentialType",
              "nodeCredentialType": "crowdStrikeOAuth2Api",
              "options": {}}
    if send_query is not None:
        params.update({"sendQuery": True, "queryParameters": {"parameters": send_query}})
    if json_body is not None:
        params.update({"sendBody": True, "specifyBody": "json", "jsonBody": json_body})
    return node(name, "n8n-nodes-base.httpRequest", 4.4, params, pos, creds=CRED_FALCON)


X = 0
def col(step=240):
    global X
    X += step
    return X


nodes = [
    node("Schedule Trigger", "n8n-nodes-base.scheduleTrigger", 1.2,
         {"rule": {"interval": [{"field": "minutes", "minutesInterval": 15}]}},
         [0, 0]),

    http_gs("get_state", "GET", "/falcon/state", [col(), 0]),

    http_falcon("falcon_query", "GET", f"{US2}/alerts/queries/alerts/v2", [col(), 0],
                send_query=[
                    # filter value in EXPRESSION mode (leading '='); host-scope dropped on purpose.
                    {"name": "filter",
                     "value": "=created_timestamp:>='{{ $('get_state').item.json.watermark }}'"},
                    {"name": "sort", "value": "created_timestamp|asc"},
                    {"name": "limit", "value": "200"},
                ]),

    http_gs("falcon_plan", "POST", "/falcon/plan", [col(), 0],
            json_body="={{ JSON.stringify({ candidate_ids: $('falcon_query').item.json.resources || [], cap: null }) }}"),

    node("IF has_new", "n8n-nodes-base.if", 2.2,
         {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose", "version": 2},
                         "conditions": [{"id": "hasnew",
                                         "leftValue": "={{ $('falcon_plan').item.json.ids.length }}",
                                         "rightValue": 0,
                                         "operator": {"type": "number", "operation": "gt"}}],
                         "combinator": "and"},
          "options": {}}, [col(), 0], nid="if-has-new"),

    http_falcon("falcon_hydrate", "POST", f"{US2}/alerts/entities/alerts/v2", [col(), 0],
                json_body="={{ JSON.stringify({ composite_ids: $('falcon_plan').item.json.ids }) }}"),

    http_gs("falcon_map", "POST", "/falcon/map", [col(), 0],
            json_body="={{ JSON.stringify({ alerts: $('falcon_hydrate').item.json.resources }) }}"),

    node("Post+Collect", "n8n-nodes-base.code", 2,
         {"mode": "runOnceForAllItems", "jsCode": JS_POST_COLLECT}, [col(), 0], nid="post-collect"),

    http_gs("falcon_advance", "POST", "/falcon/advance", [col(), 0],
            json_body="={{ JSON.stringify({ results: $('Post+Collect').item.json.results }) }}"),
]

connections = {
    "Schedule Trigger": {"main": [[{"node": "get_state", "type": "main", "index": 0}]]},
    "get_state": {"main": [[{"node": "falcon_query", "type": "main", "index": 0}]]},
    "falcon_query": {"main": [[{"node": "falcon_plan", "type": "main", "index": 0}]]},
    "falcon_plan": {"main": [[{"node": "IF has_new", "type": "main", "index": 0}]]},
    "IF has_new": {"main": [
        [{"node": "falcon_hydrate", "type": "main", "index": 0}],   # true: new alerts
        [],                                                         # false: end (poll done)
    ]},
    "falcon_hydrate": {"main": [[{"node": "falcon_map", "type": "main", "index": 0}]]},
    "falcon_map": {"main": [[{"node": "Post+Collect", "type": "main", "index": 0}]]},
    "Post+Collect": {"main": [[{"node": "falcon_advance", "type": "main", "index": 0}]]},
}

workflow = {
    "name": "falcon-alert-poller",
    "nodes": nodes,
    "connections": connections,
    "active": False,
    "settings": {"executionOrder": "v1"},
    "meta": {"templateCredsSetupCompleted": False},
    "tags": [],
}

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
out = os.path.join(_REPO_ROOT, "JSON", "falcon-alert-poller.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump(workflow, fh, indent=2, ensure_ascii=False)

with open(out, encoding="utf-8") as fh:
    reparsed = json.load(fh)
print("OK ->", out)
print("nodes:", len(reparsed["nodes"]))
print("node names:", [n["name"] for n in reparsed["nodes"]])
print("connection keys:", list(reparsed["connections"].keys()))
