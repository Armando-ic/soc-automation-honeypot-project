"""Build an importable n8n workflow JSON for falcon-contain (Phase 0D-2, human-fired Contain->Lift).

Generator/source-of-truth for JSON/falcon-contain.json. The n8n twin of the validated
scripts/falcon-contain-roundtrip.ps1: a Manual-Trigger workflow that contains the honeypot and lifts it
back, **AID-pinned** through the already-deployed grounding-service /falcon/contain-guard (hard-stop unless
the resolved host == exactly one device AND that AID == the pinned honeypot AID).

Design (deliberately simpler than runbook Section D's Wait+poll LOOPS — bounded fixed-waits instead, no
unbounded n8n loop): Manual -> resolve_host -> contain_guard -(200)-> contain -> wait 45s ->
status_contained -> lift(retry) -> wait 120s -> status_normal -> build_confirm -> Discord.
(wait_lift is 120s because CrowdStrike's lift_containment took >30s to transition in live testing 2026-06-29;
the RED build_confirm alarm remains the backstop if even 120s is not enough.)
contain_guard's 409 (error output) -> a Discord REFUSED notice and stop. lift fires regardless of the
contained read (lifting is the always-safe direction); the final Discord is GREEN only if status_normal == normal,
else a RED alarm naming the manual lift. A future hardening = the bounded poll loop + a watchdog (both deferred).

Secrets stay placeholders (REPLACE_ME cred id + Discord URL) -> re-bind on import.
Run from anywhere:  python infra/honeypot/build_falcon_contain_workflow.py

WARNING: firing this CONTAINS the honeypot (cuts RDP + Splunk UF egress) for ~the run duration; the UF
backfills on lift. Do NOT fire inside the 23:00-ET pre-shutdown window.
"""
import json
import os

CRED_FALCON = {"crowdStrikeOAuth2Api": {"id": "REPLACE_ME", "name": "Crowdstrike Falcon Account"}}
GS = "http://grounding-service:8000"
US2 = "https://api.us-2.crowdstrike.com"
DISCORD = "https://discord.com/api/webhooks/REPLACE_ME"
HOST = "vm-honeypot-win"

REFUSED_BODY = ("={{ JSON.stringify({ embeds: [{ "
                "title: '⛔ Contain REFUSED — " + HOST + "', "
                "description: 'contain-guard returned 409: the hostname did not resolve to exactly one device "
                "whose AID == the pinned honeypot AID. No contain was attempted.', "
                "color: 15158332 }] }) }}")

JS_CONFIRM = r"""// Assemble the Discord confirm/alarm embed from the two device-status reads. AID redacted.
const aid = ($('contain_guard').first().json.aid) || '';
const aidR = aid ? (aid.slice(0, 4) + '…' + aid.slice(-4)) : 'n/a';
const containedStatus = ((($('status_contained').first().json.resources) || [])[0] || {}).status || 'unknown';
const normalStatus = ((($('status_normal').first().json.resources) || [])[0] || {}).status || 'unknown';
const ok = normalStatus === 'normal';
const title = ok
  ? '✅ falcon-contain — ' + 'vm-honeypot-win restored (normal→contained→normal)'
  : '⚠️ falcon-contain — vm-honeypot-win may still be CONTAINED';
let desc = 'AID `' + aidR + '`\nObserved: **' + containedStatus + ' → ' + normalStatus + '** (target: contained → normal)';
if (!ok) {
  desc += '\n\n**Lift did not confirm `normal`.** Run the manual lift from a LOCAL machine:\n'
        + '`scripts/falcon-contain-roundtrip.ps1 -Hostname vm-honeypot-win` (its lift leg).';
}
const discord_body = { embeds: [{ title, description: desc, color: ok ? 3066993 : 15158332 }] };
return [{ json: { discord_body, containedStatus, normalStatus } }];"""


# Authoritative canvas layout, folded back from the hand-tuned n8n export (2026-06-30).
# node() looks these up by name; the per-call `pos` arg is now a fallback only.
POS = {
    "Manual Trigger": [0, 0],
    "resolve_host": [224, 0],
    "contain_guard": [448, 0],
    "Discord REFUSED": [448, 208],
    "contain": [768, 0],
    "wait_contain": [960, 0],
    "status_contained": [1184, 0],
    "lift": [1488, 0],
    "wait_lift": [1680, 0],
    "status_normal": [1872, 0],
    "build_confirm": [2080, 0],
    "Discord confirm": [2304, 0],
}


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


X = 0
def col(step=220):
    global X
    X += step
    return X


AID_BODY = "={{ JSON.stringify({ ids: [$('contain_guard').item.json.aid] }) }}"

nodes = [
    node("Manual Trigger", "n8n-nodes-base.manualTrigger", 1, {}, [0, 0], nid="manual-trigger"),

    falcon_http("resolve_host", "GET", f"{US2}/devices/queries/devices/v1", [col(), 0],
                send_query=[{"name": "filter", "value": f"hostname:'{HOST}'"}]),

    node("contain_guard", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": f"{GS}/falcon/contain-guard", "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ resolved_ids: $('resolve_host').item.json.resources || [] }) }}",
          "options": {}}, [col(), 0], nid="contain-guard", extra={"onError": "continueErrorOutput"}),

    discord("Discord REFUSED", REFUSED_BODY, [X, 200], nid="discord-refused"),

    falcon_http("contain", "POST", f"{US2}/devices/entities/devices-actions/v2?action_name=contain",
                [col(), 0], json_body=AID_BODY),

    node("wait_contain", "n8n-nodes-base.wait", 1.1, {"amount": 45, "unit": "seconds"}, [col(), 0],
         nid="wait-contain", extra={"webhookId": "falcon-contain-wait-contain"}),

    falcon_http("status_contained", "POST", f"{US2}/devices/entities/devices/v2", [col(), 0],
                json_body=AID_BODY),

    falcon_http("lift", "POST", f"{US2}/devices/entities/devices-actions/v2?action_name=lift_containment",
                [col(), 0], json_body=AID_BODY, extra={"retryOnFail": True, "waitBetweenTries": 5000}),

    node("wait_lift", "n8n-nodes-base.wait", 1.1, {"amount": 120, "unit": "seconds"}, [col(), 0],
         nid="wait-lift", extra={"webhookId": "falcon-contain-wait-lift"}),

    falcon_http("status_normal", "POST", f"{US2}/devices/entities/devices/v2", [col(), 0],
                json_body=AID_BODY),

    node("build_confirm", "n8n-nodes-base.code", 2,
         {"mode": "runOnceForAllItems", "jsCode": JS_CONFIRM}, [col(), 0], nid="build-confirm"),

    discord("Discord confirm", "={{ JSON.stringify($json.discord_body) }}", [col(), 0], nid="discord-confirm"),
]

# ---- presentation sticky notes (cosmetic; zero effect on execution) -----------
def sticky(name, content, pos, w, h, color=7):
    return {"parameters": {"content": content, "height": h, "width": w, "color": color},
            "id": "sticky-" + name.lower().replace(" ", "-").replace("—", "-"),
            "name": name, "type": "n8n-nodes-base.stickyNote", "typeVersion": 1, "position": pos}


nodes += [
    # --- documentation strip + section group-boxes (layout from the hand-tuned export, 2026-06-30) ---
    sticky("Doc — How It Works",
           "## 🔒 falcon-contain\n**What it does:** This one is human-fired. It network-isolates the honeypot "
           "through CrowdStrike, reads back the device status, then lifts it back to normal.\n\n**Why:** the "
           "SOAR pipeline only *recommends* containment, and a person is the one who actually fires this. It's the "
           "actuator for the AI-driven response playbook, with a hard safety rail built in.", [-64, -416], 460, 168, 4),
    sticky("Doc — Setup",
           "## ⚙️ Setup / prerequisites\n- **CrowdStrike OAuth2** credential (us-2).\n- **grounding-service** at "
           "`:8000` for `/falcon/contain-guard`.\n- **Discord webhook**.\n- `FALCON_PINNED_AID` set in the "
           "grounding-service `.env` (the safety pin).", [432, -416], 460, 168, 5),
    sticky("Doc — Notes",
           "## 📌 Notes / safety\n- It's **AID-pinned**: it refuses to act unless the hostname resolves to exactly "
           "one device whose AID matches the pinned honeypot AID.\n- It always attempts a self-lift in the same "
           "run, so it shouldn't leave the box offline (if the lift doesn't confirm, you get a RED alarm with the "
           "manual-lift command).\n- `wait_lift` is 120s, because CrowdStrike's lift took more than 30s to take "
           "effect in testing.\n- ⚠️ Don't fire it inside the 23:00-ET pre-shutdown window.", [928, -416], 460, 168, 6),
    sticky("Section — Resolve & Guard",
           "## ① Resolve & Guard\n**What it does:** It resolves the hostname to Falcon device IDs and then runs the "
           "AID-pin guard. If that isn't exactly one device matching the pinned AID, the guard returns a 409, which "
           "posts a Discord **REFUSED** notice and stops the run.\n\n**Why:** it's the *pin*, not the hostname, that "
           "bounds the blast radius, so it can never isolate the wrong box.", [-64, -208], 700, 576, "#030303"),
    sticky("Section — Contain & Verify",
           "## ② Contain & Verify\n**What it does:** It network-isolates the pinned device, waits 45 seconds, then "
           "reads the device status to see whether it went `contained`.\n\n**Why:** read it back rather than just "
           "assume. The observed status is captured and shown in the final Discord summary (the run proceeds to "
           "lift either way).", [704, -208], 660, 460, "#030303"),
    sticky("Section — Lift & Confirm",
           "## ③ Lift & Confirm\n**What it does:** It lifts the containment (retrying if needed), waits 120 seconds, "
           "reads the status again, and builds the Discord embed. The embed is GREEN only if the device is observed "
           "back to `normal`, otherwise it's a RED alarm that includes the manual-lift command.\n\n**Why:** it should "
           "never give a false all-clear, and restoring egress is always the safe direction to fail in.", [1424, -208], 1094, 460, "#030303"),
]

connections = {
    "Manual Trigger": {"main": [[{"node": "resolve_host", "type": "main", "index": 0}]]},
    "resolve_host": {"main": [[{"node": "contain_guard", "type": "main", "index": 0}]]},
    "contain_guard": {"main": [
        [{"node": "contain", "type": "main", "index": 0}],            # output 0: success (aid)
        [{"node": "Discord REFUSED", "type": "main", "index": 0}],    # output 1: 409 error -> refused + stop
    ]},
    "contain": {"main": [[{"node": "wait_contain", "type": "main", "index": 0}]]},
    "wait_contain": {"main": [[{"node": "status_contained", "type": "main", "index": 0}]]},
    "status_contained": {"main": [[{"node": "lift", "type": "main", "index": 0}]]},
    "lift": {"main": [[{"node": "wait_lift", "type": "main", "index": 0}]]},
    "wait_lift": {"main": [[{"node": "status_normal", "type": "main", "index": 0}]]},
    "status_normal": {"main": [[{"node": "build_confirm", "type": "main", "index": 0}]]},
    "build_confirm": {"main": [[{"node": "Discord confirm", "type": "main", "index": 0}]]},
}

workflow = {
    "name": "falcon-contain",
    "nodes": nodes,
    "connections": connections,
    "active": False,
    "settings": {"executionOrder": "v1"},
    "meta": {"templateCredsSetupCompleted": False},
    "tags": [],
}

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
out = os.path.join(_REPO_ROOT, "JSON", "falcon-contain.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump(workflow, fh, indent=2, ensure_ascii=False)

with open(out, encoding="utf-8") as fh:
    reparsed = json.load(fh)
print("OK ->", out)
print("nodes:", len(reparsed["nodes"]))
print("node names:", [n["name"] for n in reparsed["nodes"]])
