"""Build an importable n8n workflow JSON for honeypot-logon-alert (Part B, session 42):
the "you know the moment it fell" alert. Generator/source-of-truth for
JSON/honeypot-logon-alert.json.

  Logon Webhook (/honeypot-logon-alert) -> Build Logon Alert (Code) -> Discord Logon Alert

ONE workflow serves BOTH successful-logon saved searches, selecting its embed from the Splunk
envelope's search_name. THREE-WAY severity, defaulting to CRITICAL, and honest about what it knows:

  search_name == PRIMARY  ("honeypot-weak-cred-logon") -> the box fell            -> CRITICAL, and
      this is the ONLY branch that may claim the weak-credential tripwire actually fired.
  search_name == BACKSTOP ("honeypot-any-logon")       -> somebody logged in (minus the measured
      SYSTEM Type-5 noise) -> heads-up (mostly your own ~3x/day admin logons).
  anything else (unknown / renamed / malformed)        -> CRITICAL, but it does NOT assert the
      tripwire fired -- it only knows a successful logon arrived under an UNRECOGNIZED alert name,
      which is either a real compromise or a misnamed saved search. Escalate, say what is known.

WHY DEFAULT TO CRITICAL. Downgrading a real compromise to a mild ping is the dangerous failure, so
only the recognized backstop is ever downgraded; everything else escalates. Same logic as the SPL's
"denylist the measured noise, never allowlist the types". A drifted backstop name costs a false
CRITICAL on your own admin logon; a drifted primary name can never downgrade. The two saved-search
NAMES are load-bearing -- they are also written into section 3 of honeypot-brake-triggers.md so the
Splunk-side names and these constants cannot silently drift (pinned by a test).

WHY THROUGH n8n, NEVER SPLUNK -> DISCORD DIRECTLY. Discord's webhook API needs a body carrying
`content` or `embeds`; Splunk's built-in webhook alert action sends a FIXED envelope
({sid, search_name, app, owner, results_link, result}) with neither, so a direct POST scores 400 and
the ping never arrives. Proven live 2026-07-16. Same fixed envelope that killed section 1's host
feeder. Route through n8n like the brake.

SAME ENVELOPE, OPPOSITE VERDICT vs the brake -- but note the part that is NOT yet proven on this box.
The brake needed the whole row SET (fan-out is a set property, so `result` = first-row-only destroyed
the signal). This alert is one logon = one row, and Splunk runs the saved search with trigger "for
each result", which is EXPECTED to send one webhook per row (result = that row's fields). The
Discord-400 half is proven live; the per-result-per-row half is NOT -- verify at B6c (fire two
distinct logons in one window, confirm two n8n executions each with its own row) before trusting it.
Even if Splunk batched or sent first-row-only, this alert still ALARMS (fail-safe critical); it would
only under-report concurrent distinct logons.

THE CODE NODE NEVER THROWS. The webhook is unauthenticated on the private SOC network, and a logon
alert that throws is a silent miss on the one event this build exists to catch. Every line that
touches the (untrusted) body is inside a try; the catch depends only on HOST, so a malformed body
degrades to an ALARMING ping, not a red execution that drops the notification.

results_link (the one-click pivot into Splunk the envelope carries for free) is rendered as an embed
link, and _time is epoch-aware (the live webhook has delivered epoch-seconds floats). Both are
runtime-only, in the operator's own Discord; the committed workflow carries no real URL/IP.

Secrets stay placeholders (REPLACE_ME Discord URL, re-bound on import). No credentials: the Discord
secret lives in the URL, and the webhook is unauthenticated on the private SOC network. The embed
titles carry literal emoji glyphs, exactly as honeypot-brake does (the .py and the generated .json
are UTF-8); they are display text, not secrets, and the scrub gate has cleared the same pattern.

Run from anywhere:  python infra/honeypot/build_honeypot_logon_alert_workflow.py
"""
import json
import os

DISCORD = "https://discord.com/api/webhooks/REPLACE_ME"
HOST = "vm-honeypot-win"

# The saved-search names the operator MUST give the two Splunk alerts. Load-bearing: the Code node
# recognizes them by name to select the embed, and anything else escalates. They are also written
# into honeypot-brake-triggers.md section 3 (pinned by test_logon_search_names_are_documented_...).
BACKSTOP_SEARCH_NAME = "honeypot-any-logon"
PRIMARY_SEARCH_NAME = "honeypot-weak-cred-logon"

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(_REPO_ROOT, "JSON", "honeypot-logon-alert.json")

# Linear chain, so these positions are cosmetic (no fan-out to order by canvas position, unlike
# honeypot-brake where A10 made the y values load-bearing).
POS = {
    "Logon Webhook": [0, 0],
    "Build Logon Alert": [240, 0],
    "Discord Logon Alert": [480, 0],
}


def node(name, ntype, tv, params, nid=None, extra=None):
    n = {"parameters": params, "id": nid or name.lower().replace(" ", "-"), "name": name,
         "type": ntype, "typeVersion": tv, "position": POS[name]}
    if extra:
        n.update(extra)
    return n


# The embed builder. %%HOST%% / %%BACKSTOP%% / %%PRIMARY%% are Python-side placeholders (the Code
# node JS uses no n8n {{ }} expressions, so a %% token cannot collide with anything n8n evaluates).
# The emoji are literal glyphs (U+26A0 U+FE0F warning, U+1F6A8 rotating light), like honeypot-brake.
_JS_BUILD = r"""// honeypot-logon-alert: build the Discord embed for a successful logon.
// ONE workflow serves both saved searches. Splunk's built-in webhook action (trigger: for each
// result) POSTs a FIXED envelope { result:{<one row>}, sid, results_link, search_name, owner, app }.
// `result` is that single row -- _time, src_ip, user, Logon_Type, ComputerName -- every value a
// STRING (Splunk types all webhook/oneshot fields as strings).
//
// THREE-WAY SEVERITY, defaulting to CRITICAL, honest about what it knows:
//   * search_name == PRIMARY  -> CRITICAL, and the ONLY branch that may claim the weak-credential
//                                tripwire fired (that branch knows the box fell).
//   * search_name == BACKSTOP -> heads-up (mostly your own ~3x/day admin logons).
//   * anything else           -> CRITICAL, but it does NOT assert the tripwire fired: it only knows
//                                a logon arrived under an UNRECOGNIZED alert name (real compromise
//                                OR a misnamed saved search). Escalate, say what is actually known.
// Downgrading a real compromise to a mild ping is the dangerous failure, so only the recognized
// backstop is ever downgraded. Read the body defensively and NEVER throw: this webhook is
// unauthenticated on the private SOC net, so a malformed body must still fire an alarming ping.
const BACKSTOP_SEARCH_NAME = "%%BACKSTOP%%";
const PRIMARY_SEARCH_NAME = "%%PRIMARY%%";
const HOST = "%%HOST%%";

// EVERYTHING that touches the (untrusted, unauthenticated) input lives inside this try, so no
// malformed body can throw past it and drop the ping. Only the consts above sit outside, and the
// catch depends solely on HOST + e, so the node truly cannot throw: it always returns an embed.
let discord_body;
try {
  const first = $input.first() || {};
  const outer = (first && first.json) ? first.json : {};
  const body = (outer && typeof outer.body === 'object' && outer.body) ? outer.body : outer;
  const result = (body && typeof body.result === 'object' && body.result) ? body.result : {};
  const searchName = (body && body.search_name != null) ? String(body.search_name) : '';

  // Bound every attacker-influenceable field. An account name / src_ip is short in practice, but on
  // the backstop path the attacker CREATES the account, so cap the rendered length to keep the
  // embed well under Discord's limits and unbreakable by a pathological value. JSON.stringify
  // downstream escapes the content; this only bounds length. … is the ellipsis.
  const cap = (v, n) => {
    const str = (v == null) ? '' : String(v);
    return str.length > n ? str.slice(0, n) + '…' : str;
  };

  // _time often arrives as an epoch-seconds float (live Splunk webhook, session 33), and "the
  // moment it fell" must not show a raw Unix timestamp. Convert a plausible CURRENT epoch to ISO
  // UTC; pass everything else through untouched. Bounded to EXACTLY 10 integer digits on purpose:
  // a current unix-seconds value is 10 digits (through year 2286), and reformatting a 9- or
  // 11-digit number would render a confidently WRONG date (1973 / 5138), which is worse than an
  // obvious raw number. A 13-digit ms epoch (not what Splunk sends) also shows raw, which is safe.
  const fmtTime = (v) => {
    const str = (v == null) ? '' : String(v).trim();
    if (/^\d{10}(\.\d+)?$/.test(str)) {
      const d = new Date(parseFloat(str) * 1000);
      if (!isNaN(d.getTime())) return d.toISOString() + ' (UTC)';
    }
    return str;
  };

  const sn = searchName.trim().toLowerCase();
  const isPrimary = sn === PRIMARY_SEARCH_NAME.toLowerCase();
  const isBackstop = sn === BACKSTOP_SEARCH_NAME.toLowerCase();

  const user = cap(result.user, 200) || 'unknown';
  const srcIp = cap(result.src_ip, 200) || 'unknown';
  const logonType = cap(result.Logon_Type, 40) || 'n/a';
  const when = cap(fmtTime(result._time), 60) || 'n/a';
  const computer = cap(result.ComputerName, 120) || HOST;
  const fired = cap(searchName, 200) || 'unknown';

  // The one-click pivot into Splunk, present in the envelope for free. Render it ONLY when it is
  // plainly http(s): we refuse to surface a non-http value (it is never the real deep link), which
  // also keeps a junk value out of the embed. Trimmed for consistency with fmtTime, so a link with
  // stray surrounding whitespace is not silently dropped.
  const rawLink = (body && body.results_link != null) ? String(body.results_link).trim() : '';
  const pivot = /^https?:\/\//i.test(rawLink) ? '\n[→ open in Splunk](' + cap(rawLink, 400) + ')' : '';

  const detail =
    'account: **' + user + '**\n' +
    'from src_ip: **' + srcIp + '**\n' +
    'logon type: ' + logonType + ', when: ' + when + '\n' +
    'host: ' + computer + '\n' +
    'fired by: `' + fired + '`' + pivot;

  // isPrimary is checked FIRST so escalation wins by construction: the amber downgrade below is
  // structurally gated on !isPrimary. (The two names are distinct constants, so they are already
  // mutually exclusive; this is belt-and-braces against anyone ever setting them equal.)
  if (isPrimary) {
    discord_body = { embeds: [{
      title: '🚨 HONEYPOT COMPROMISED - ' + HOST,
      description: 'A successful logon fired the weak-credential tripwire (`' + fired + '`). ' +
        '**Consider the box compromised.**\n\n' + detail +
        '\n\nCapture telemetry (B8), then tear down from the pre-open snapshot (B9). Do NOT reopen ' +
        'until you know how it fell.',
      color: 15158332 }] };
  } else if (isBackstop) {
    discord_body = { embeds: [{
      title: '⚠️ Honeypot logon - ' + HOST,
      description: 'A successful logon on the honeypot.\n\n' + detail +
        '\n\nIf this was YOU, note it (spec section 4, prep step 5) so a real hit is not mistaken ' +
        'for your own admin session. If it was NOT you, treat the box as compromised and start the ' +
        'B8 capture.',
      color: 16776960 }] };
  } else {
    discord_body = { embeds: [{
      title: '🚨 HONEYPOT logon: UNRECOGNIZED alert - ' + HOST,
      description: 'A successful logon fired an alert that is NOT the recognized benign backstop. ' +
        'Either the box fell or a saved search is misnamed - treat as compromise until you confirm ' +
        'which.\n\n' + detail +
        '\n\nIf `fired by` above is not one of your two configured searches, fix the saved-search ' +
        'name; otherwise start the B8 capture.',
      color: 15158332 }] };
  }
} catch (e) {
  // A logon alert that throws is a silent miss on the one event this build exists to catch.
  // Fail TOWARD the alarm: send an alarming ping with whatever is known and let the operator dig.
  discord_body = { embeds: [{
    title: '🚨 HONEYPOT logon alert - ' + HOST,
    description: 'A successful-logon alert fired but building the detail failed (' +
      ((e && e.message) ? e.message : String(e)) + '). A logon happened on the honeypot - ' +
      'check Splunk NOW.',
    color: 15158332 }] };
}
return [{ json: { discord_body } }];"""

JS_BUILD = (_JS_BUILD
            .replace("%%BACKSTOP%%", BACKSTOP_SEARCH_NAME)
            .replace("%%PRIMARY%%", PRIMARY_SEARCH_NAME)
            .replace("%%HOST%%", HOST))


def sticky(name, content, pos, w, h, color=7):
    return {"parameters": {"content": content, "height": h, "width": w, "color": color},
            "id": "sticky-" + name.lower().replace(" ", "-"),
            "name": name, "type": "n8n-nodes-base.stickyNote", "typeVersion": 1, "position": pos}


nodes = [
    # Splunk POSTs here, EXPECTED to be one request per matching result row (trigger: for each
    # result) -- but that per-row half is unverified until B6c (see the module docstring); the node
    # alarms either way. Default responseMode (onReceived) is correct: Splunk ignores the response.
    node("Logon Webhook", "n8n-nodes-base.webhook", 2.1,
         {"httpMethod": "POST", "path": "honeypot-logon-alert", "options": {}},
         extra={"webhookId": "honeypot-logon-alert"}),

    node("Build Logon Alert", "n8n-nodes-base.code", 2, {"jsCode": JS_BUILD}),

    # Terminal. Retry a transient Discord 429/5xx (this is the whole point of the alert), and let a
    # persistent failure go RED so a dead delivery path is visible rather than silently swallowed.
    node("Discord Logon Alert", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": DISCORD, "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify($json.discord_body) }}", "options": {}},
         extra={"retryOnFail": True, "maxTries": 3}),
]

nodes += [
    sticky("Doc - Logon Alert",
           "## 🚨 honeypot-logon-alert\n**What it does:** Splunk is EXPECTED to fire one webhook per "
           "successful-logon row (verify at B6c); this workflow builds a Discord embed and POSTs "
           "it.\n\n**One "
           "workflow, two searches, keyed on `search_name` (name them EXACTLY):**\n- `" +
           PRIMARY_SEARCH_NAME + "` (the weak cred was used) -> 🚨 **CRITICAL**\n- `" +
           BACKSTOP_SEARCH_NAME + "` (somebody logged in) -> ⚠️ heads-up\n\n**Severity defaults to "
           "CRITICAL:** only the recognized backstop name is downgraded; the primary and any renamed "
           "search escalate, and only the primary claims the tripwire fired. A drifted backstop name "
           "= a false critical on your own logon; a drifted primary name never downgrades.\n\n**Never "
           "Splunk -> Discord directly** (fixed envelope, no embeds -> 400).",
           [-40, -340], 520, 300, 4),
]

connections = {
    "Logon Webhook": {"main": [[{"node": "Build Logon Alert", "type": "main", "index": 0}]]},
    "Build Logon Alert": {"main": [[{"node": "Discord Logon Alert", "type": "main", "index": 0}]]},
    # Discord Logon Alert is terminal.
}

workflow = {
    "name": "honeypot-logon-alert",
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
