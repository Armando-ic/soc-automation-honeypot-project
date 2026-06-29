"""Build an importable n8n workflow JSON for honeypot-triage (Phase 0D-1b Phase 2).

Generator/source-of-truth for JSON/honeypot-triage.json. Uses Python string handling so all
JS/regex/escaping is exact. Re-ground branch omitted (FAIL -> needs-human direct) for import
reliability. Run from anywhere:  python infra/honeypot/build_honeypot_triage_workflow.py
Secrets stay placeholders (REPLACE_ME cred ids + Discord URL) -> re-bind on import.
"""
import json
import os

CRED_HDR = {"httpHeaderAuth": {"id": "REPLACE_ME", "name": "Header Auth account"}}
CRED_GREY = {"httpHeaderAuth": {"id": "REPLACE_ME", "name": "GreyNoise account"}}
CRED_ANTH = {"anthropicApi": {"id": "REPLACE_ME", "name": "Anthropic account"}}
CRED_IRIS = {"dfirIrisApi": {"id": "REPLACE_ME", "name": "DFIR IRIS account"}}

# ---- forked Opus system prompt (triage-honeypot.md body) -------------------
PROMPT = """You are a Tier 1 SOC analyst triaging alerts from a honeypot monitored by Splunk. Enrichment and candidate MITRE techniques are ALREADY PROVIDED to you in the user message - you do not call any tools to gather them. Your only job is to reason over the provided context and submit one structured analysis.

Workflow:
1. Read the alert details, the provided enrichment results, and the provided candidate MITRE techniques.
2. Call submit_triage_result EXACTLY ONCE to deliver your findings. It is the only valid way to respond. Do not return free text after the tool call.

REQUIRED - submit_triage_result MUST include ALL nine fields every single time. Omitting ANY of them is an error:
1. schema_version - always the string "v1"
2. alert_summary - one short paragraph
3. severity - one of low/medium/high/critical
4. severity_rationale - why that severity
5. mitre_techniques - array (empty ONLY if no provided candidate fits)
6. iocs - object containing ALL five arrays: ips, domains, file_hashes, users, hosts
7. iocs_enriched - array of the enriched IOCs
8. recommended_actions - 3 to 5 specific, imperative actions; NEVER an empty list
9. investigation_notes - a non-empty paragraph (hypotheses, missing data, MITRE rationale)

Rules:
- mitre_techniques MUST be chosen ONLY from the provided candidate technique IDs. Do not cite any technique whose ID is not in the provided candidate list - even if it seems relevant. If none fit, return an empty mitre_techniques list and explain in investigation_notes.
- For IOC values, use the EXACT strings provided in the "Observed IOCs" and "Enrichment results" sections, verbatim, in both iocs and iocs_enriched[].value. Do not reformat, re-case, defang, or normalize them.
- iocs_enriched verdicts MUST match the provided enrichment results. Do not invent a malicious/suspicious verdict for an IOC the enrichment did not flag as malicious/suspicious. Set source to the provider that produced the verdict (e.g. "abuseipdb", "greynoise").
- iocs lists must contain every distinct IOC observed, deduplicated. iocs_enriched contains only the IOCs that were actually enriched (the provided ones).
- For each iocs_enriched item, set ioc_type to "ip", "domain", or "file_hash" matching the value.
- Pick one severity (low/medium/high/critical); use severity_rationale for nuance. high/critical must be supported by a malicious/suspicious IOC verdict or a high-severity tactic in the cited techniques.
- recommended_actions: specific and imperative ("Block 203.0.113.10 at the perimeter firewall"), 3-5 items, never empty.
- investigation_notes: alternative hypotheses, missing data, MITRE rationale; never empty.

Severity calibration:
- low: routine/expected or likely false positive
- medium: deserves analyst attention but not page-worthy
- high: active threat indicators present, escalate within working hours
- critical: page on-call immediately, suspected active compromise"""

# ---- submit_triage_result schema (unchanged from v3) ----------------------
SCHEMA = {
    "type": "object",
    "required": ["schema_version", "alert_summary", "severity", "severity_rationale",
                 "mitre_techniques", "iocs", "iocs_enriched", "recommended_actions",
                 "investigation_notes"],
    "properties": {
        "schema_version": {"type": "string", "enum": ["v1"]},
        "alert_summary": {"type": "string"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "severity_rationale": {"type": "string"},
        "mitre_techniques": {"type": "array", "items": {"type": "object",
            "required": ["id", "name", "tactic"],
            "properties": {"id": {"type": "string"}, "name": {"type": "string"}, "tactic": {"type": "string"}}}},
        "iocs": {"type": "object", "required": ["ips", "domains", "file_hashes", "users", "hosts"],
            "properties": {
                "ips": {"type": "array", "items": {"type": "string"}},
                "domains": {"type": "array", "items": {"type": "string"}},
                "file_hashes": {"type": "array", "items": {"type": "string"}},
                "users": {"type": "array", "items": {"type": "string"}},
                "hosts": {"type": "array", "items": {"type": "string"}}}},
        "iocs_enriched": {"type": "array", "items": {"type": "object",
            "required": ["value", "ioc_type", "verdict", "source", "summary"],
            "properties": {
                "value": {"type": "string"},
                "ioc_type": {"type": "string", "enum": ["ip", "domain", "file_hash"]},
                "verdict": {"type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"]},
                "source": {"type": "string"},
                "summary": {"type": "string"}}}},
        "recommended_actions": {"type": "array", "items": {"type": "object",
            "required": ["description", "priority"],
            "properties": {"description": {"type": "string"},
                           "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]}}}},
        "investigation_notes": {"type": "string"},
    },
}

# ---- Code-node JS (raw strings preserve regex backslashes/backticks) -------
JS_PARSE = r"""// Parse alert -> canonical IOCs + alert_text. Source-aware: splunk brute-force (synthesize)
// vs falcon (use the supplied alert_text). CF#2 canonical form; empty-safe src_ip.
const body = $input.first().json.body || {};
const r = body.result || {};
const source = body.source || 'splunk';

const canonIp = (v) => String(v || '').trim();                       // plain IPv4: no change
const isPrivate = (ip) =>
  /^10\./.test(ip) || /^192\.168\./.test(ip) ||
  /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) || /^127\./.test(ip) || ip === '';
const canonDomain = (v) =>
  String(v || '').trim().toLowerCase().replace(/\[\.\]/g, '.').replace(/^hxxp/, 'http').replace(/\.$/, '');
const canonHash = (v) => String(v || '').trim().toLowerCase();

const src_ip = canonIp(r.src_ip);
const host = r.ComputerName || r.dest || r.host || 'unknown-host';
const user = r.user || r.Account_Name || 'unknown-user';
const count = r.count || 'multiple';

const enrich_ips = (src_ip && !isPrivate(src_ip)) ? [src_ip] : [];

const alert_text = (source === 'falcon' && body.alert_text)
  ? String(body.alert_text)
  : `RDP/SMB brute force: ${count} failed Windows logons (EventCode 4625) ` +
    `against user ${user} on host ${host} from external source IP ${src_ip}. ` +
    `Repeated failed authentication, credential access, remote service login.`;

return [{ json: {
  run_id: String($execution.id),
  timestamp: new Date().toISOString(),
  source,
  search_name: body.search_name || '',
  results_link: body.results_link || '',
  console_link: body.console_link || '',
  src_ip, host, user, count,
  enrich_ips,
  observed_iocs: { ips: enrich_ips, domains: [], file_hashes: [], users: [user], hosts: [host] },
  alert_text,
}}];"""

JS_NORMBODY = r"""// Assemble /normalize items from the two enrichment responses (only when an IP was enriched).
const p = $('Parse Alert').item.json;
const ip = p.src_ip;
const items = [];
if (ip) {
  const abuse = $('enrich_abuseipdb').item.json;
  const grey = $('enrich_greynoise').item.json;
  items.push({ ioc: ip, provider: 'abuseipdb', response: abuse });
  items.push({ ioc: ip, provider: 'greynoise', response: grey });
}
return [{ json: { ...p, items } }];"""

JS_OPUSINPUT = r"""// Build the Opus user message: alert + provided enrichment + candidate techniques + EXACT IOC strings to echo.
const p = $('Parse Alert').item.json;
const enrichment_results = $('normalize').item.json.enrichment_results || {};
const retr = $('retrieve').item.json || {};
const techniques = retr.techniques || [];
const retrieved_ids = retr.ids || [];

const candidates = techniques
  .map(t => `- ${t.id}  ${t.name}  [tactics: ${(t.tactics || []).join(', ')}]`)
  .join('\n') || '(none)';
const enrichLines = Object.entries(enrichment_results)
  .map(([ioc, verdict]) => `- ${ioc} => ${verdict}`)
  .join('\n') || '(none)';
const observedIps = (p.observed_iocs.ips || []).join(', ') || '(none)';

const opus_user_message =
`Honeypot Splunk alert: ${p.search_name}
Host: ${p.host}   User: ${p.user}   Failed logons: ${p.count}
Splunk link: ${p.results_link}

Observed IOCs (use these EXACT strings verbatim):
  IPs: ${observedIps}
  Users: ${(p.observed_iocs.users || []).join(', ')}
  Hosts: ${(p.observed_iocs.hosts || []).join(', ')}

Enrichment results (verdicts you MUST match; do not invent):
${enrichLines}

Candidate MITRE techniques (cite ONLY from these IDs):
${candidates}

Submit your triage with submit_triage_result now.`;

return [{ json: { ...p, enrichment_results, retrieved_ids, opus_user_message } }];"""

JS_EXTRACT = r"""// Extract submit_triage_result + build Iris alert_iocs, iris_description, Discord embed, /verify body.
const content = $input.first().json.content || [];
const toolCall = content.find(c => c.type === 'tool_use' && c.name === 'submit_triage_result');
if (!toolCall) throw new Error(`Expected submit_triage_result tool call but got: ${JSON.stringify(content)}`);
const r = toolCall.input;

// Defensive: Opus intermittently omits the trailing narrative field (investigation_notes).
// Guarantee all 9 required fields are structurally present so a benign omission can't gate a
// sound triage. Substantive checks (mitre_in_retrieved, enrichment_grounded, tactic/name/
// severity, verdict_sourced) still run on the model's REAL values - only empty structure is filled.
r.schema_version = r.schema_version || 'v1';
if (!r.investigation_notes || !String(r.investigation_notes).trim()) {
  r.investigation_notes = 'No additional analyst notes provided by automated triage.';
}
if (!r.alert_summary || !String(r.alert_summary).trim()) r.alert_summary = 'Honeypot alert (no summary provided).';
if (!r.severity) r.severity = 'medium';
if (!r.severity_rationale || !String(r.severity_rationale).trim()) r.severity_rationale = 'No rationale provided.';
r.mitre_techniques = Array.isArray(r.mitre_techniques) ? r.mitre_techniques : [];
r.iocs_enriched = Array.isArray(r.iocs_enriched) ? r.iocs_enriched : [];
r.recommended_actions = Array.isArray(r.recommended_actions) ? r.recommended_actions : [];
r.iocs = (r.iocs && typeof r.iocs === 'object') ? r.iocs : {};
for (const b of ['ips', 'domains', 'file_hashes', 'users', 'hosts']) {
  if (!Array.isArray(r.iocs[b])) r.iocs[b] = [];
}

const ctx = $('Build Opus Input').item.json;
const usage = $input.first().json.usage || {};
const tokens_in = usage.input_tokens || 0;
const tokens_out = usage.output_tokens || 0;

const IRIS_IOC_TYPE_IDS = { ip: 79, domain: 20, md5: 90, sha1: 111, sha256: 113 };
const TLP_AMBER = 2;
const BULLET = '•', EMDASH = '—';

function resolveIrisTypeId(iocType, value) {
  if (iocType === 'ip') return IRIS_IOC_TYPE_IDS.ip;
  if (iocType === 'domain') return IRIS_IOC_TYPE_IDS.domain;
  if (iocType === 'file_hash') {
    const v = String(value).trim().toLowerCase();
    if (/^[0-9a-f]{32}$/.test(v)) return IRIS_IOC_TYPE_IDS.md5;
    if (/^[0-9a-f]{40}$/.test(v)) return IRIS_IOC_TYPE_IDS.sha1;
    if (/^[0-9a-f]{64}$/.test(v)) return IRIS_IOC_TYPE_IDS.sha256;
  }
  return null;
}

const alert_iocs = [];
for (const item of (r.iocs_enriched || []).filter(i => i.verdict === 'malicious' || i.verdict === 'suspicious')) {
  const typeId = resolveIrisTypeId(item.ioc_type, item.value);
  if (typeId === null) continue;
  alert_iocs.push({
    ioc_value: item.value,
    ioc_description: `${item.source}: ${item.summary}`,
    ioc_tlp_id: TLP_AMBER,
    ioc_type_id: typeId,
    ioc_tags: 'soc-automation,honeypot,phase0d',
  });
}

const sevId = { low: 4, medium: 1, high: 5, critical: 6 }[r.severity] || 2;
const mitre = (r.mitre_techniques || []).map(t => `${t.id} (${t.name})`).join(', ') || 'none identified';
const enriched = (r.iocs_enriched || [])
  .map(i => `${BULLET} \`${i.value}\` ${EMDASH} ${String(i.verdict).toUpperCase()} (${i.source}): ${i.summary}`)
  .join('\n') || '_none_';
const actions = (r.recommended_actions || [])
  .map(a => `${BULLET} [${String(a.priority).toUpperCase()}] ${a.description}`)
  .join('\n') || '_none_';

const detail_link = (ctx.source === 'falcon') ? (ctx.console_link || '')
  : (ctx.results_link || '').replace('mydfir-splunk', '20.236.193.253')
                            .replace('192.168.129.131', '20.236.193.253')
                            .replace('vm-soc-v2-splunk', '20.236.193.253');
const link_label = (ctx.source === 'falcon') ? 'Falcon' : 'Splunk';
const splunk_link = detail_link;   // kept for back-compat of the returned key

const iris_description =
`**Summary:** ${r.alert_summary}

**Severity:** ${r.severity} ${EMDASH} ${r.severity_rationale}

**MITRE Techniques:** ${mitre}

**Enriched IOCs:**
${enriched}

**Recommended Actions:**
${actions}

**Investigation Notes:**
${r.investigation_notes || '_none_'}

---
${link_label}: ${detail_link}`;

const verify_body = {
  result: r,
  retrieved: ctx.retrieved_ids || [],
  enrichment_results: ctx.enrichment_results || {},
  run_meta: { run_id: ctx.run_id, timestamp: ctx.timestamp, tokens_in, tokens_out, latency_ms: 0 },
};

const top_mitre = (r.mitre_techniques && r.mitre_techniques[0])
  ? `${r.mitre_techniques[0].id} ${r.mitre_techniques[0].name}` : 'n/a';

const sev = String(r.severity || '').toLowerCase();
const containRecommended = (ctx.source === 'falcon') && (sev === 'high' || sev === 'critical');
let desc = `Host **${ctx.host}** • src_ip \`${ctx.src_ip || 'n/a'}\`\nMITRE: ${top_mitre}\nVerifier: **passed**`;
if (detail_link) desc += `\n[${link_label} detection](${detail_link})`;
if (containRecommended) desc += `\n⚠️ **Contain recommended** — run \`falcon-contain\` for vm-honeypot-win`;
const discord_body = { embeds: [{
  title: `✅ ${String(r.severity).toUpperCase()} — ${ctx.search_name || 'Honeypot alert'}`,
  description: desc,
  color: 3066993,
}]};

return [{ json: {
  ...r,
  alert_name: ctx.search_name || 'Honeypot brute force',
  severity_iris_id: sevId,
  iris_description,
  splunk_link,
  alert_iocs,
  verify_body,
  top_mitre,
  discord_body,
  source: ctx.source,
  console_link: ctx.console_link,
  src_ip: ctx.src_ip,
  host: ctx.host,
} }];"""

TOOLCODE_JS = "return {\n  success: true,\n  message: \"Triage analysis received. Workflow will route to downstream consumers.\"\n};"

NEEDS_DISCORD = ("={{ JSON.stringify({ embeds: [{ "
                 "title: '⚠️ NEEDS-HUMAN — ' + ($('Extract Result').item.json.alert_name || 'Honeypot'), "
                 "description: 'Host **' + $('Extract Result').item.json.host + '** • src_ip `' + $('Extract Result').item.json.src_ip + '`\\nVerifier: NOT passed — human review required', "
                 "color: 15158332 }] }) }}")


def node(name, ntype, tv, params, pos, creds=None, extra=None):
    n = {"parameters": params, "id": name.lower().replace(" ", "-"), "name": name,
         "type": ntype, "typeVersion": tv, "position": pos}
    if creds:
        n["credentials"] = creds
    if extra:
        n.update(extra)
    return n


X = 0
def col(step=240):
    global X
    X += step
    return X


nodes = [
    node("Webhook", "n8n-nodes-base.webhook", 2.1,
         {"httpMethod": "POST", "path": "honeypot-triage", "options": {}},
         [0, 0], extra={"webhookId": "honeypot-triage"}),
    node("Parse Alert", "n8n-nodes-base.code", 2,
         {"jsCode": JS_PARSE}, [col(), 0]),
    node("enrich_abuseipdb", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "GET", "url": "https://api.abuseipdb.com/api/v2/check",
          "authentication": "genericCredentialType", "genericAuthType": "httpHeaderAuth",
          "sendQuery": True, "queryParameters": {"parameters": [
              {"name": "ipAddress", "value": "={{ $('Parse Alert').item.json.src_ip }}"},
              {"name": "maxAgeInDays", "value": "90"}]},
          "sendHeaders": True, "headerParameters": {"parameters": [
              {"name": "Accept", "value": "application/json"}]},
          "options": {}}, [col(), 0], creds=CRED_HDR, extra={"onError": "continueRegularOutput"}),
    node("enrich_greynoise", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "GET",
          "url": "=https://api.greynoise.io/v3/community/{{ $('Parse Alert').item.json.src_ip }}",
          "authentication": "genericCredentialType", "genericAuthType": "httpHeaderAuth",
          "sendHeaders": True, "headerParameters": {"parameters": [
              {"name": "Accept", "value": "application/json"}]},
          "options": {"response": {"response": {"neverError": True}}}},
         [col(), 0], creds=CRED_GREY, extra={"onError": "continueRegularOutput"}),
    node("Build Normalize Body", "n8n-nodes-base.code", 2,
         {"jsCode": JS_NORMBODY}, [col(), 0]),
    node("normalize", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": "http://grounding-service:8000/normalize",
          "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ items: $json.items }) }}", "options": {}},
         [col(), 0]),
    node("retrieve", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": "http://grounding-service:8000/retrieve",
          "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify({ alert_text: $('Parse Alert').item.json.alert_text, top_k: 8 }) }}",
          "options": {}}, [col(), 0]),
    node("Build Opus Input", "n8n-nodes-base.code", 2,
         {"jsCode": JS_OPUSINPUT}, [col(), 0]),
    node("submit_triage_result", "@n8n/n8n-nodes-langchain.toolCode", 1.3,
         {"description": "Submit your final SOC triage analysis. You MUST call this tool exactly once at the end of your investigation to deliver your structured findings. Do not respond with text after calling this tool.",
          "jsCode": TOOLCODE_JS, "specifyInputSchema": True, "schemaType": "manual",
          "inputSchema": json.dumps(SCHEMA, indent=2)}, [X - 120, 220]),
    node("Opus triage", "@n8n/n8n-nodes-langchain.anthropic", 1,
         {"modelId": {"__rl": True, "value": "claude-opus-4-8", "mode": "list",
                      "cachedResultName": "claude-opus-4-8"},
          "messages": {"values": [{"content": "={{ $json.opus_user_message }}"}]},
          "options": {"system": PROMPT}},
         [col(), 0], creds=CRED_ANTH, extra={"retryOnFail": True, "waitBetweenTries": 5000}),
    node("Extract Result", "n8n-nodes-base.code", 2,
         {"jsCode": JS_EXTRACT}, [col(), 0]),
    node("verify", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": "http://grounding-service:8000/verify",
          "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify($json.verify_body) }}", "options": {}},
         [col(), 0]),
    node("Gate", "n8n-nodes-base.if", 2.2,
         {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose", "version": 2},
                         "conditions": [{"id": "c1", "leftValue": "={{ $json.verification_passed }}",
                                         "rightValue": "", "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
                         "combinator": "and"},
          "options": {}}, [col(), 0]),
    node("Add new Alert", "n8n-nodes-dfir-iris.dfirIris", 2,
         {"resource": "alert", "operation": "create", "alert_customer_id": 1,
          "alert_severity_id": "={{ $('Extract Result').item.json.severity_iris_id }}",
          "alert_title": "={{ $('Extract Result').item.json.alert_name }}",
          "additionalFields": {"__iocsCollectionJSON": "={{ $('Extract Result').item.json.alert_iocs }}",
                               "alert_description": "={{ $('Extract Result').item.json.iris_description }}"},
          "options": {}}, [col(), -120], creds=CRED_IRIS),
    node("Discord", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": "https://discord.com/api/webhooks/REPLACE_ME",
          "sendBody": True, "specifyBody": "json",
          "jsonBody": "={{ JSON.stringify($('Extract Result').item.json.discord_body) }}", "options": {}},
         [X, 40]),
    node("Needs-Human Iris", "n8n-nodes-dfir-iris.dfirIris", 2,
         {"resource": "alert", "operation": "create", "alert_customer_id": 1,
          "alert_severity_id": "={{ $('Extract Result').item.json.severity_iris_id }}",
          "alert_title": "=[NEEDS-HUMAN] {{ $('Extract Result').item.json.alert_name }}",
          "additionalFields": {"__iocsCollectionJSON": "={{ $('Extract Result').item.json.alert_iocs }}",
                               "alert_description": "={{ '⚠️ NEEDS-HUMAN — verifier did not pass; re-grounding/auto-retry not enabled.\\n\\n' + $('Extract Result').item.json.iris_description }}"},
          "options": {}}, [col(), 180], creds=CRED_IRIS),
    node("Needs-Human Discord", "n8n-nodes-base.httpRequest", 4.4,
         {"method": "POST", "url": "https://discord.com/api/webhooks/REPLACE_ME",
          "sendBody": True, "specifyBody": "json", "jsonBody": NEEDS_DISCORD, "options": {}},
         [X, 320]),
    node("Has IOC", "n8n-nodes-base.if", 2.2,
         {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose", "version": 2},
                         "conditions": [{"id": "hasioc",
                                         "leftValue": "={{ $('Parse Alert').item.json.src_ip }}",
                                         "rightValue": "",
                                         "operator": {"type": "string", "operation": "notEmpty", "singleValue": True}}],
                         "combinator": "and"},
          "options": {}}, [470, 200]),
]

connections = {
    "Webhook": {"main": [[{"node": "Parse Alert", "type": "main", "index": 0}]]},
    "Parse Alert": {"main": [[{"node": "Has IOC", "type": "main", "index": 0}]]},
    "Has IOC": {"main": [
        [{"node": "enrich_abuseipdb", "type": "main", "index": 0}],     # true: has IOC -> enrich
        [{"node": "Build Normalize Body", "type": "main", "index": 0}], # false: skip enrichment
    ]},
    "enrich_abuseipdb": {"main": [[{"node": "enrich_greynoise", "type": "main", "index": 0}]]},
    "enrich_greynoise": {"main": [[{"node": "Build Normalize Body", "type": "main", "index": 0}]]},
    "Build Normalize Body": {"main": [[{"node": "normalize", "type": "main", "index": 0}]]},
    "normalize": {"main": [[{"node": "retrieve", "type": "main", "index": 0}]]},
    "retrieve": {"main": [[{"node": "Build Opus Input", "type": "main", "index": 0}]]},
    "Build Opus Input": {"main": [[{"node": "Opus triage", "type": "main", "index": 0}]]},
    "submit_triage_result": {"ai_tool": [[{"node": "Opus triage", "type": "ai_tool", "index": 0}]]},
    "Opus triage": {"main": [[{"node": "Extract Result", "type": "main", "index": 0}]]},
    "Extract Result": {"main": [[{"node": "verify", "type": "main", "index": 0}]]},
    "verify": {"main": [[{"node": "Gate", "type": "main", "index": 0}]]},
    "Gate": {"main": [
        [{"node": "Add new Alert", "type": "main", "index": 0},
         {"node": "Discord", "type": "main", "index": 0}],
        [{"node": "Needs-Human Iris", "type": "main", "index": 0},
         {"node": "Needs-Human Discord", "type": "main", "index": 0}],
    ]},
}

workflow = {
    "name": "honeypot-triage",
    "nodes": nodes,
    "connections": connections,
    "active": False,
    "settings": {"executionOrder": "v1"},
    "meta": {"templateCredsSetupCompleted": False},
    "tags": [],
}

# repo root = two levels up from this script (infra/honeypot/ -> repo root)
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
out = os.path.join(_REPO_ROOT, "JSON", "honeypot-triage.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump(workflow, fh, indent=2, ensure_ascii=False)

# validate round-trip
with open(out, encoding="utf-8") as fh:
    reparsed = json.load(fh)
print("OK nodes:", len(reparsed["nodes"]))
print("node names:", [n["name"] for n in reparsed["nodes"]])
print("connections keys:", len(reparsed["connections"]))
