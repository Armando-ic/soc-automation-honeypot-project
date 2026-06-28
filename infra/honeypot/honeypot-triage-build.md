# Honeypot Triage — n8n build & ops runbook (Phase 0D-1b Phase 2)

The hands-on, node-by-node guide for building the **`honeypot-triage`** n8n workflow that wires the live
grounding-service into a credibility-gated SOAR loop on honeypot brute-force telemetry. Build the workflow by
hand in the n8n UI following Section B (node list) + Section C (Code-node JS), then export to
`JSON/honeypot-triage.json` (sanitized).

- **Design spec:** `docs/superpowers/specs/2026-06-28-honeypot-phase0d1b-phase2-wire-design.md`
- **Plan:** `docs/superpowers/plans/2026-06-28-honeypot-phase0d1b-phase2-wire.md`
- **Forks:** `JSON/SOC-Triage-v3.json` (flipped to deterministic up-front enrichment).
- **Opus system prompt:** `triage-verifier/prompts/triage-honeypot.md`.

---

## Section A — Prerequisites

- `vm-soc-v2-n8n` running; `grounding-service`, `qdrant`, `n8n` containers Up on the `soar-net` network; the
  live judge wired (Section F). From the n8n container: `docker exec n8n wget -qO- http://grounding-service:8000/health`
  → `{"status":"ok"}`.
- `vm-soc-v2-splunk` running; `index=honeypot` receiving (Plan 0A). Honeypot host generating brute-force data.
- n8n credentials present: AbuseIPDB (Header Auth "Header Auth account"), VirusTotal ("VirusTotal account"),
  Anthropic ("Anthropic account"), DFIR-Iris ("DFIR IRIS account"). **New this phase:** GreyNoise key,
  Discord webhook URL (Section E).
- Service base URL from n8n: `http://grounding-service:8000` (loopback over `soar-net`, no auth, never public).

---

## Section B — Node list + connections

Build in this order (positions are cosmetic). The integration-critical endpoints are `/normalize`,
`/retrieve`, `/verify` on `http://grounding-service:8000`.

1. **Webhook** — `n8n-nodes-base.webhook`, HTTP Method POST, Path = (let n8n generate a UUID). Record the
   **production** URL (`http://<n8n-host>:5678/webhook/<uuid>`) for the Splunk action (Section D / Task 7).
2. **Parse Alert** — `n8n-nodes-base.code` (Run Once for All Items). JS = Section C.1.
3. **enrich_abuseipdb** — `n8n-nodes-base.httpRequest`. GET `https://api.abuseipdb.com/api/v2/check`;
   Authentication = Generic Credential Type / Header Auth ("Header Auth account"); Send Query Parameters:
   `ipAddress = {{ $json.src_ip }}`, `maxAgeInDays = 90`; Send Headers: `Accept: application/json`.
4. **enrich_greynoise** — `n8n-nodes-base.httpRequest`. GET
   `https://api.greynoise.io/v3/community/{{ $json.src_ip }}`; Authentication = Header Auth ("GreyNoise account",
   header name `key`); Options → Response → **"Never Error" = ON** (a 404 "IP not observed" must normalize to
   `unknown`, not fail the run).
5. **Build Normalize Body** — `n8n-nodes-base.code` (Run Once for All Items). JS = Section C.2.
6. **normalize** — `n8n-nodes-base.httpRequest`. POST `http://grounding-service:8000/normalize`; Specify Body =
   Using JSON; Body = `={{ { "items": $json.items } }}`. Returns `{enrichment_results:{...}}`.
7. **retrieve** — `n8n-nodes-base.httpRequest`. POST `http://grounding-service:8000/retrieve`; Body (JSON) =
   `={{ { "alert_text": $('Parse Alert').item.json.alert_text, "top_k": 8 } }}`. Returns `{techniques, ids}`.
8. **Build Opus Input** — `n8n-nodes-base.code` (Run Once for All Items). JS = Section C.3.
9. **submit_triage_result** — `@n8n/n8n-nodes-langchain.toolCode`. Copy verbatim from `JSON/SOC-Triage-v3.json`
   (description, jsCode, and the full `inputSchema` — **schema unchanged**).
10. **Opus triage** — `@n8n/n8n-nodes-langchain.anthropic` "Message a model". Model = `claude-opus-4-8`;
    Credentials = "Anthropic account"; `retryOnFail` = ON, wait 5000 ms; System = full text of
    `triage-verifier/prompts/triage-honeypot.md`; Message content = `={{ $json.opus_user_message }}`. Connect
    `submit_triage_result` → this node's **ai_tool** input. **Do NOT connect any enrichment tool** (enrichment
    is deterministic now).
11. **Extract Result** — `n8n-nodes-base.code` (Run Once for All Items). JS = Section C.4.
12. **verify** — `n8n-nodes-base.httpRequest`. POST `http://grounding-service:8000/verify`; Body (JSON) =
    `={{ $json.verify_body }}`. Returns the run record incl. `verification_passed`.
13. **Gate** — `n8n-nodes-base.if`. Condition (Boolean): `={{ $json.verification_passed }}` is `true`.
14. **Add new Alert** — `n8n-nodes-dfir-iris.dfirIris`. Copy v3's config verbatim (resource alert / create;
    `alert_customer_id:1`; `alert_severity_id = {{ $json.severity_iris_id }}`; `alert_title = {{ $json.alert_name }}`;
    additionalFields `__iocsCollectionJSON = {{ $json.alert_iocs }}` (passed raw, not stringified — v3 Gotcha N1),
    `alert_description = {{ $json.iris_description }}`).
15. **Discord** — `n8n-nodes-base.httpRequest`. POST `<Discord webhook URL>`; Body (JSON) =
    `={{ $json.discord_body }}`. Keep the real URL OUT of the exported JSON (Task 9): either store it in a
    credential, or replace with `https://discord.com/api/webhooks/REPLACE_ME` before commit.
16. **Build Reground Input** — `n8n-nodes-base.code` (FAIL branch). JS = Section C.5 (first block).
17. **Opus triage 2** — duplicate of node 10, Message content = `={{ $json.opus_user_message_reground }}`;
    connect the same `submit_triage_result` tool.
18. **Extract Result 2 / verify 2 / Gate 2** — duplicates of nodes 11–13 on the re-ground branch.
19. **Needs-Human** — duplicate **Add new Alert** (title prefixed `[NEEDS-HUMAN]`, description appends the
    offending checks) + a **Discord** post flagged needs-human (`verdict = 'needs-human'`, Section C.5).

### Connections

```
Webhook → Parse Alert → enrich_abuseipdb → enrich_greynoise → Build Normalize Body → normalize → retrieve →
Build Opus Input → Opus triage → Extract Result → verify → Gate
Gate(true)  → Add new Alert → Discord
Gate(false) → Build Reground Input → Opus triage 2 → Extract Result 2 → verify 2 → Gate 2
Gate 2(true)  → Add new Alert → Discord          (shared targets — wire Gate 2's true output into node 14)
Gate 2(false) → Needs-Human (Iris) → Needs-Human (Discord)
submit_triage_result → (ai_tool) Opus triage   AND   → (ai_tool) Opus triage 2
```

---

## Section C — Code nodes (full JS)

### C.1 — Parse Alert

```javascript
// Parse honeypot brute-force alert -> canonical IOCs + alert_text + enrichment plan (CF#2 canonical form).
const body = $input.first().json.body || {};
const r = body.result || {};

const canonIp = (v) => String(v || '').trim();                       // plain IPv4: no change
const isPrivate = (ip) =>
  /^10\./.test(ip) || /^192\.168\./.test(ip) ||
  /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) || /^127\./.test(ip) || ip === '';
// domain/hash canonicalizers included for 0D-2 readiness (unused for 4625):
const canonDomain = (v) =>
  String(v || '').trim().toLowerCase().replace(/\[\.\]/g, '.').replace(/^hxxp/, 'http').replace(/\.$/, '');
const canonHash = (v) => String(v || '').trim().toLowerCase();

const src_ip = canonIp(r.src_ip);
const host = r.ComputerName || r.dest || r.host || 'unknown-host';
const user = r.user || r.Account_Name || 'unknown-user';
const count = r.count || 'multiple';

const enrich_ips = (src_ip && !isPrivate(src_ip)) ? [src_ip] : [];

const alert_text =
  `RDP/SMB brute force: ${count} failed Windows logons (EventCode 4625) ` +
  `against user ${user} on host ${host} from external source IP ${src_ip}. ` +
  `Repeated failed authentication, credential access, remote service login.`;

return [{ json: {
  run_id: String($execution.id),
  timestamp: new Date().toISOString(),
  search_name: body.search_name || '',
  results_link: body.results_link || '',
  src_ip, host, user, count,
  enrich_ips,
  observed_iocs: { ips: enrich_ips, domains: [], file_hashes: [], users: [user], hosts: [host] },
  alert_text,
}}];
```

### C.2 — Build Normalize Body

```javascript
// Assemble /normalize items from the two enrichment responses, keyed by the canonical src_ip.
const p = $('Parse Alert').item.json;
const ip = p.src_ip;
const abuse = $('enrich_abuseipdb').item.json;       // AbuseIPDB raw response
const grey = $('enrich_greynoise').item.json;        // GreyNoise community raw response
const items = [];
if (ip) {
  items.push({ ioc: ip, provider: 'abuseipdb', response: abuse });
  items.push({ ioc: ip, provider: 'greynoise', response: grey });
}
return [{ json: { ...p, items } }];
```

> Note: `/normalize`'s `normalize_abuseipdb` reads `response.data.abuseConfidenceScore`; if the AbuseIPDB node
> returns the raw API envelope (`{data:{...}}`) this works directly. `normalize_greynoise` reads
> `response.classification` (GreyNoise community returns `benign`/`malicious`/`unknown` → clean/malicious/unknown).

### C.3 — Build Opus Input

```javascript
// Build the Opus user message: alert + provided enrichment + candidate techniques + EXACT IOC strings to echo.
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

return [{ json: {
  ...p,
  enrichment_results,
  retrieved_ids,
  opus_user_message,
}}];
```

### C.4 — Extract Result

```javascript
// Extract submit_triage_result + build Iris alert_iocs, iris_description, Discord embed, and /verify body.
const content = $input.first().json.content || [];
const toolCall = content.find(c => c.type === 'tool_use' && c.name === 'submit_triage_result');
if (!toolCall) throw new Error(`Expected submit_triage_result tool call but got: ${JSON.stringify(content)}`);
const r = toolCall.input;

// carry-forward context from earlier nodes
const ctx = $('Build Opus Input').item.json;
const usage = $input.first().json.usage || {};
const tokens_in = usage.input_tokens || 0;       // best-effort (langchain node may not expose usage)
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

// Azure Splunk public IP (was local mydfir-splunk/192.168.129.131 in v3)
const splunk_link = (ctx.results_link || '').replace('mydfir-splunk', '20.236.193.253')
                                            .replace('192.168.129.131', '20.236.193.253');

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
Splunk: ${splunk_link}`;

const verify_body = {
  result: r,
  retrieved: ctx.retrieved_ids || [],
  enrichment_results: ctx.enrichment_results || {},
  run_meta: {
    run_id: ctx.run_id, timestamp: ctx.timestamp,
    tokens_in, tokens_out, latency_ms: 0,
  },
};

const top_mitre = (r.mitre_techniques && r.mitre_techniques[0])
  ? `${r.mitre_techniques[0].id} ${r.mitre_techniques[0].name}` : 'n/a';

// Discord embed (PASS path verdict). For the Needs-Human Discord node, set verdict = 'needs-human'.
const verdict = 'passed';
const discord_body = { embeds: [{
  title: `${verdict === 'passed' ? '✅' : '⚠️'} ${String(r.severity).toUpperCase()} — ${ctx.search_name || 'Honeypot brute force'}`,
  description: `Host **${ctx.host}** • src_ip \`${ctx.src_ip}\`\nMITRE: ${top_mitre}\nVerifier: **${verdict}**`,
  color: verdict === 'passed' ? 3066993 : 15158332,
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
  src_ip: ctx.src_ip, host: ctx.host,
}}];
```

### C.5 — Build Reground Input (+ Needs-Human Discord note)

```javascript
// Build Reground Input (FAIL branch): re-ask Opus with the offending checks as corrective feedback.
const ctx = $('Build Opus Input').item.json;
const report = $('verify').item.json;
const failed = (report.check_results || [])
  .filter(c => c.status === 'failed')
  .map(c => `- ${c.name}: ${c.detail} ${c.offending && c.offending.length ? '(' + c.offending.join(', ') + ')' : ''}`)
  .join('\n') || '(unknown)';
const opus_user_message_reground =
`${ctx.opus_user_message}

YOUR PREVIOUS RESULT FAILED THESE VERIFIER CHECKS — revise and resubmit:
${failed}

Cite ONLY candidate technique IDs listed above and echo the EXACT provided IOC strings.`;
return [{ json: { ...ctx, opus_user_message_reground } }];
```

> **Needs-Human Discord:** in the Needs-Human branch's Extract Result 2 (or a small Set node), set
> `verdict = 'needs-human'` when building `discord_body` so the embed shows ⚠️ + red and the Iris title is
> prefixed `[NEEDS-HUMAN]`. Append the failed-checks list to the Iris `alert_description`.

---

## Section D — Splunk saved-search (trigger)

SPL (tune field names to your 4625 sourcetype; honeypot `index=honeypot`):

```spl
index=honeypot (EventCode=4625 OR source="XmlWinEventLog:Security" EventCode=4625)
| where NOT (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip)
             OR cidrmatch("192.168.0.0/16", src_ip) OR src_ip="-" OR isnull(src_ip))
| stats count, values(user) as user, values(ComputerName) as ComputerName,
        earliest(_time) as earliest, latest(_time) as latest by src_ip
| where count >= 10
| eval ComputerName=mvindex(ComputerName,0), user=mvindex(user,0)
```

- **Alert type:** Scheduled, cron `*/5 * * * *`, time range last 5 min.
- **Trigger:** for each result. **Throttle:** by `src_ip` for **300 s** (once per src_ip per window).
- **Action:** Webhook → the n8n **production** webhook URL (node 1). Splunk posts
  `{search_name, results_link, result:{...row...}}`, matching Parse Alert (C.1).

---

## Section E — Discord webhook setup

Discord → Server Settings → Integrations → Webhooks → New Webhook → pick the channel → Copy Webhook URL. Store
it in `Personal/honeypot-secrets.txt` (gitignored). The embed payload is built by Extract Result (C.4); the
Discord node (node 15) POSTs `={{ $json.discord_body }}` to the URL. Keep the URL out of the committed JSON.

---

## Section F — Live judge

On the VM, next to `grounding-service/docker-compose.yml`, create a gitignored `.env`:

```
ANTHROPIC_API_KEY=<key>
```

Ensure compose references it (`env_file: [.env]` or `environment: ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}`),
then `docker compose -f grounding-service/docker-compose.yml up -d --build`. `main.py` auto-switches
`StubJudge → ClaudeJudge` when the key is present. The judge is **advisory only** — status hardcoded
`NEEDS_HUMAN`, notes are untrusted display text, it never flips the gate.

---

## Section G — e2e test procedure

1. **Happy path:** with the honeypot generating brute-force traffic (or replay the pinned sample by POSTing to
   the production webhook), confirm a DFIR-Iris alert + Discord embed + a `runs.jsonl` line with
   `verification_passed:true`, `mitre_in_retrieved` + `enrichment_grounded` **live** (passed), and a `judge`
   entry with a real advisory note (status needs_human). Check: `docker exec grounding-service sh -c 'tail -1 /data/runs.jsonl'`.
2. **Failure path:** force a bad triage (set `top_k=1` on `retrieve`, or pin a crafted Opus output citing
   `T9999`) so `mitre_in_retrieved` fails → re-ground → still fails → Needs-Human (Iris `[NEEDS-HUMAN]` +
   Discord flagged), `runs.jsonl` line `verification_passed:false`. Restore `top_k=8`.
3. **Aggregate:** `docker exec grounding-service python -c "from triage_verifier.run_logger import aggregate; print(aggregate('/data/runs.jsonl'))"`.

---

## Section H — Troubleshooting

- **`mitre_in_retrieved` FAIL on a correct triage** → the cited technique wasn't retrieved. Widen `top_k`
  (node 7) or improve `alert_text` wording (C.1) so the right family ranks in the top-k.
- **`enrichment_grounded` FAIL** → IOC-string drift. Confirm the Parse Alert canonical form (C.1) equals the
  string Opus echoed in `iocs_enriched[].value` (CF#2). The prompt forbids reformatting — re-check the prompt.
- **GreyNoise 404 / workflow errors on unseen IPs** → ensure node 4 has Options → Response → "Never Error" ON;
  `/normalize` maps an absent classification to `unknown`.
- **Iris IOC silently dropped** → unresolved `ioc_type` in `resolveIrisTypeId` (e.g. a hash of unexpected
  length). Check the value/type.
- **`verify` returns a `verifier_error` check** → a real exception inside the verifier (CF#1 caught it and
  gated false instead of 500). Inspect `docker logs grounding-service`.
- **`/normalize` returns all `unknown`** → the enrichment node returned an envelope shape the normalizer
  doesn't read; confirm AbuseIPDB returns `{data:{abuseConfidenceScore}}` and GreyNoise returns
  `{classification}` at the top level (adjust C.2 to unwrap if your HTTP node nests under `.body`/`.data`).
