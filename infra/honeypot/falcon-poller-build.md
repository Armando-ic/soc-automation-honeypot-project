# Falcon poller + human-fired Contain — n8n build & ops runbook (Phase 0D-2)

The hands-on, node-by-node guide for the three n8n pieces that graft a **CrowdStrike Falcon source** onto the
already-live `honeypot-triage` loop:

1. **`falcon-alert-poller`** — scheduled poll of the Falcon Alerts API → map each new alert into the **existing
   Splunk-shaped body** → POST to the `honeypot-triage` webhook. Includes the **containment watchdog**.
2. **`falcon-contain`** — human-fired, **AID-pinned** `Contain → Lift` (the n8n twin of
   `scripts/falcon-contain-roundtrip.ps1`).
3. Re-import of the **edited `honeypot-triage`** (the three A′ edits).

All deterministic logic lives in the **grounding-service** (`/falcon/*` routes, pytest-tested); these n8n
workflows are pure orchestration. Field names are the ones **confirmed on us-2** in
[`falcon-alerts-field-map.md`](falcon-alerts-field-map.md).

- **Design spec:** `docs/superpowers/specs/2026-06-29-honeypot-phase0d2-falcon-trigger-contain-design.md`
- **Plan:** `docs/superpowers/plans/2026-06-29-honeypot-phase0d2-falcon-trigger-contain.md`
- **Endpoints (loopback over `soar-net`, never public):** `http://grounding-service:8000/falcon/{state,plan,map,advance,contain-guard}`

---

## Section A — Prerequisites

- `vm-soc-v2-n8n` running; `grounding-service` + `qdrant` + `n8n` Up on `soar-net`. Verify the new routes:
  `docker exec grounding-service curl -s localhost:8000/falcon/state` → `{"watermark":...,"seen":[...]}`.
- `FALCON_PINNED_AID` set in `/root/soc-src/grounding-service/.env`; container recreated (0D-2 Task 6).
- The watermark is **seeded** (Task 6) so the first poll is bounded.
- Falcon trial active (expires **2026-07-13**); `honeypot-soar` API client (Alerts R/W, Hosts R/W).
- Splunk saved-search (`honeypot-triage` Splunk trigger) is **unchanged** — the poller is an *additional* source.

---

## Section B — Falcon credential (n8n's built-in **CrowdStrike OAuth2 API** type)

n8n ships a dedicated CrowdStrike credential (`crowdStrikeOAuth2Api`) — use it (not the generic "OAuth2 API").
In n8n → **Credentials → New → "CrowdStrike OAuth2 API"**, name it **`Falcon account`**:
- **URL:** `https://api.us-2.crowdstrike.com`  ← **critical**: this targets our **us-2** cloud (default is us-1).
  The credential mints/refreshes the 30-min bearer at `{URL}/oauth2/token`.
- **Client ID / Client Secret:** the `honeypot-soar` values (load from `Personal/honeypot-vm-creds.txt`).

⚠️ **The credential's connection test may show "unsuccessful"** — n8n tests it with the `usermgmt:read` scope,
which `honeypot-soar` does **not** have (it has Alerts R/W + Hosts R/W + Event streams R). **This is expected and
harmless**: the credential still mints a valid token and every Alerts/Hosts call below works. To make the test
green (optional), add **User management: Read** to the `honeypot-soar` client in the Falcon console (read-only;
does not rotate the secret).

Every Falcon HTTP node below uses **Authentication = Predefined Credential Type → CrowdStrike OAuth2 API →
`Falcon account`** (it injects the bearer; you still type the full us-2 URL in the node).

---

## Section C — `falcon-alert-poller` (new workflow)

### C.0 Node list + connections

```
Schedule Trigger ─┬─> get_state ─> falcon_query ─> falcon_plan ─> IF has_new
                  │                                                  ├─(true)─> falcon_hydrate ─> falcon_map ─> Post+Collect ─> falcon_advance
                  │                                                  └─(false)─> (end)
                  └─> wd_resolve ─> wd_guard ─> wd_status ─> IF wd_contained ─(true)─> wd_lift ─> wd_alarm
```

### C.1 Schedule Trigger
- `n8n-nodes-base.scheduleTrigger`; interval **every 15 minutes**.
- Two outgoing connections: → `get_state` (poll branch) **and** → `wd_resolve` (watchdog branch).

### C.2 get_state — `n8n-nodes-base.httpRequest`
- **GET** `http://grounding-service:8000/falcon/state`. Returns `{watermark, seen}`.

### C.3 falcon_query — `n8n-nodes-base.httpRequest` (Auth: OAuth2 `Falcon account`)
- **GET** `https://api.us-2.crowdstrike.com/alerts/queries/alerts/v2`
- **Send Query Parameters = ON** (3 params; set the `filter` value to **Expression** mode):
  - `filter` = `created_timestamp:>='{{ $('get_state').item.json.watermark }}'`
  - `sort` = `created_timestamp|asc`
  - `limit` = `200`
- Returns `resources` = ordered `composite_id`s, oldest-first. **Proven live (n8n 2.21.7 / httpRequest v4.4,
  2026-06-29):** `total:1`, `resources:["306e…0772:ind:9134…5865:…995344"]` (the EICAR detection; its embedded
  AID == the pinned honeypot AID).
- **⚠️ Host-scope (`device.hostname:'vm-honeypot-win'`) dropped on purpose.** The spec'd `+device.hostname` FQL
  **AND** clause could NOT be transmitted through n8n 2.21.7: (a) Send-Query-Parameters sends the FQL `+` as a
  literal `+` → the CrowdStrike gateway decodes it to a space → `total:0`; (b) moving the whole query to the URL
  field with `%2B` → httpRequest v4.4 re-encodes the `%` to `%252B` → **`400 invalid query filter`**. The tenant
  is **honeypot-only** and Contain is **AID-pinned**, so filtering on `created_timestamp` alone is safe — a stray
  host's alert would at worst be triaged as noise, and the Contain AID-guard still refuses any non-pinned AID.
  Re-add the host clause only if (i) a reliable n8n encoding for the FQL `+` is found AND (ii) a second host ever
  legitimately shares the tenant.

### C.4 falcon_plan — `n8n-nodes-base.httpRequest`
- **POST** `http://grounding-service:8000/falcon/plan`; Body (JSON):
  `={{ JSON.stringify({ candidate_ids: $('falcon_query').item.json.resources || [], cap: null }) }}`
- Returns `{ids}` (seen-deduped + capped, oldest-first).

### C.5 IF has_new — `n8n-nodes-base.if`
- Condition (number): `={{ $('falcon_plan').item.json.ids.length }}` **is greater than** `0`.
- **true** → `falcon_hydrate`; **false** → leave unconnected (poll ends; watchdog still ran in parallel).

### C.6 falcon_hydrate — `n8n-nodes-base.httpRequest` (Auth: OAuth2 `Falcon account`)
- **POST** `https://api.us-2.crowdstrike.com/alerts/entities/alerts/v2`; Body (JSON):
  `={{ JSON.stringify({ composite_ids: $('falcon_plan').item.json.ids }) }}`
- Returns `resources` = full alert objects.

### C.7 falcon_map — `n8n-nodes-base.httpRequest`
- **POST** `http://grounding-service:8000/falcon/map`; Body (JSON):
  `={{ JSON.stringify({ alerts: $('falcon_hydrate').item.json.resources }) }}`
- Returns `{items:[{body, composite_id, created}]}` (oldest-first).

### C.8 Post+Collect — `n8n-nodes-base.code` (Run Once for All Items)
Posts each mapped body to the triage webhook **in order**, stops at the first failure (so a partial failure
never double-triages a later alert), and returns the ordered ack list. The grounding-service `advance_state`
then only honors the contiguous-ok prefix → a SKIP is impossible.

```javascript
// Post each Falcon-mapped alert to the existing honeypot-triage webhook, oldest-first, collecting ack results.
// .first() (not .item): this node is "Run Once for All Items" so there is no current item for .item to pair to;
// the whole chain is single-item, so .first() reads the one falcon_map output deterministically.
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
return [{ json: { results } }];
```

### C.9 falcon_advance — `n8n-nodes-base.httpRequest`
- **POST** `http://grounding-service:8000/falcon/advance`; Body (JSON):
  `={{ JSON.stringify({ results: $('Post+Collect').item.json.results }) }}`
- Persists `{watermark, seen}` to `/data/falcon-poller-state.json`. Returns the new state.

### C.10 Watchdog branch (off the Schedule Trigger, parallel)
Auto-Lifts a stuck containment (the one always-safe action — it only ever restores).
- **wd_resolve** — `httpRequest` (OAuth2 `Falcon account`): **GET**
  `=https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=hostname:'vm-honeypot-win'` → `resources`.
- **wd_guard** — `httpRequest`: **POST** `http://grounding-service:8000/falcon/contain-guard`; Body:
  `={{ JSON.stringify({ resolved_ids: $('wd_resolve').item.json.resources || [] }) }}`. Returns `{aid}` (only the
  pinned host passes). Set **On Error = Continue (using error output)** and leave the error output unconnected
  (a guard miss just means "don't touch it").
- **wd_status** — `httpRequest` (OAuth2): **POST**
  `https://api.us-2.crowdstrike.com/devices/entities/devices/v2`; Body:
  `={{ JSON.stringify({ ids: [$('wd_guard').item.json.aid] }) }}` → read `resources[0].status`.
- **IF wd_contained** — `={{ $('wd_status').item.json.resources[0].status }}` **equals** `contained`.
  - **true** → **wd_lift** — `httpRequest` (OAuth2): **POST**
    `https://api.us-2.crowdstrike.com/devices/entities/devices-actions/v2?action_name=lift_containment`; Body:
    `={{ JSON.stringify({ ids: [$('wd_guard').item.json.aid] }) }}` → then **wd_alarm** (Discord): a loud
    "⚠️ watchdog auto-lifted a stuck containment on vm-honeypot-win" embed.
  - **false** → end.

> The watchdog is intentionally simple: any `contained` it observes is treated as stuck, because the human-fired
> `falcon-contain` lifts within its own single run. This makes an overnight stuck-contain self-heal on the next
> tick / morning startup.

---

## Section D — `falcon-contain` (new workflow, human-fired, AID-pinned)

### D.0 Node list
```
Manual Trigger ─> resolve_host ─> contain_guard ─(200)─> contain ─> poll_contained ─> lift ─> poll_normal ─> Discord confirm
                                       └─(409 error output)─> Discord REFUSED alarm (stop)
                                                                                      (lift fail)─> Discord LOUD alarm (manual-lift runbook)
```

### D.1 Manual Trigger
- `n8n-nodes-base.manualTrigger` (or a Form Trigger with field `hostname`, default `vm-honeypot-win`). MVP: a
  Set node hardcoding `hostname = vm-honeypot-win`.

### D.2 resolve_host — `httpRequest` (OAuth2 `Falcon account`)
- **GET** `=https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=hostname:'vm-honeypot-win'` → `resources`.

### D.3 contain_guard — `httpRequest` (the safety rail)
- **POST** `http://grounding-service:8000/falcon/contain-guard`; Body:
  `={{ JSON.stringify({ resolved_ids: $('resolve_host').item.json.resources || [] }) }}`.
- **On Error = Continue (using error output).** The **200** path yields `{aid}` (== the pinned honeypot AID).
- Wire the **error output** (HTTP 409 = ≠1 host or non-pinned AID) → a **Discord "⚠️ Contain REFUSED — hostname
  did not resolve to the pinned honeypot AID"** node, then **stop** (no `contain` call is reachable from here).

### D.4 contain — `httpRequest` (OAuth2)
- **POST** `https://api.us-2.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain`; Body:
  `={{ JSON.stringify({ ids: [$('contain_guard').item.json.aid] }) }}`.

### D.5 poll_contained — Wait + `httpRequest` loop
- **Wait** 10s → **POST** `https://api.us-2.crowdstrike.com/devices/entities/devices/v2`; Body:
  `={{ JSON.stringify({ ids: [$('contain_guard').item.json.aid] }) }}` → **IF** `resources[0].status == 'contained'`:
  false → loop back to Wait (cap ~12 iterations); true → `lift`.

### D.6 lift — `httpRequest` (OAuth2), **retryOnFail = ON, waitBetweenTries = 5000**
- **POST** `https://api.us-2.crowdstrike.com/devices/entities/devices-actions/v2?action_name=lift_containment`;
  Body: `={{ JSON.stringify({ ids: [$('contain_guard').item.json.aid] }) }}`.

### D.7 poll_normal — Wait + `httpRequest` loop (as D.5, until `status == 'normal'`)
- On success → **Discord confirm** (`normal → contained → normal`, redacted AID) + optionally append a
  `runs.jsonl` note.
- If `normal` is never reached → a **loud red Discord alarm** that names the **out-of-band manual lift**:
  run `scripts/falcon-contain-roundtrip.ps1 -Hostname vm-honeypot-win` (its lift leg) from a local machine.

> ⚠️ Containment cuts the honeypot's egress (Splunk UF + RDP) while active — the UF queues + backfills on lift.
> **Do not fire `falcon-contain` inside the 23:00-ET pre-shutdown window.**

---

## Section E — Re-import the edited `honeypot-triage` (the A′ edits)

The builder (`build_honeypot_triage_workflow.py`) already regenerated `JSON/honeypot-triage.json` (18 nodes:
source-aware Parse Alert, `Has IOC` empty-IOC guard, Extract Result `source`/`console_link` + Contain line).

1. n8n → Workflows → **Import from File** → `JSON/honeypot-triage.json` (or update in place; keep webhook path
   `honeypot-triage`).
2. **Re-bind credentials** (they don't travel with the JSON): `enrich_abuseipdb`→`Header Auth account`,
   `enrich_greynoise`→`GreyNoise account`, `Opus triage`→`Anthropic account`, `Add new Alert` +
   `Needs-Human Iris`→`DFIR IRIS account`; set the real **Discord** webhook URL on `Discord` + `Needs-Human Discord`.
3. Re-activate. Confirm the Splunk action still posts to `http://10.0.0.6:5678/webhook/honeypot-triage`.
4. **Smoke the Splunk path** (pin a Splunk-shaped body, no `source` key) → green Iris + Discord, **no** Contain
   line. **Smoke the Falcon empty-IOC path** (pin `{"body":{"source":"falcon","alert_text":"…T1204…","result":
   {"src_ip":"","user":"","ComputerName":"vm-honeypot-win","count":1}}}`) → run completes to needs-human, does
   **not** 422.

---

## Section F — e2e validation (Task 11)

1. **Empty-IOC e2e:** let the poller pick up a real no-IP behavioral Falcon alert → completes to needs-human +
   `runs.jsonl` line, no 422.
2. **Contain-path e2e:** needs a **credential-access / IOC-bearing** alert at High (the verifier's
   `severity_supported` won't pass a no-IOC Execution alert at High). When one exists: triage passes the gate →
   green Discord with **"⚠️ Contain recommended — run falcon-contain for vm-honeypot-win"** → fire `falcon-contain`
   → `normal → contained → normal`.
3. **No-Contain majority:** a typical alert flows through with no Contain line.
4. **Watchdog:** drive `falcon-contain` to `contained`, then run the poller's watchdog branch → auto-lift + alarm.
5. **Idempotency:** run the poller twice → second run re-pulls nothing new (`/falcon/state` watermark stable, no
   duplicate Iris alerts).

---

## Section G — Troubleshooting

- **falcon_query 400 / FQL error** → check the `filter` param encoding; confirm `created_timestamp` is the FQL key
  (it is on us-2) and the watermark is a valid ISO8601 string.
- **falcon_plan returns no ids but alerts exist** → the watermark is ahead of them (re-seed via
  `POST /falcon/advance` with an older `created`), or they're all in `seen`.
- **/falcon/contain-guard always 409** → `FALCON_PINNED_AID` not set in the VM `.env`, or the resolved AID ≠ pin.
- **advance never moves the watermark** → the `created` field is empty; confirm `falcon_map` returned a non-empty
  `created` (it reads `created_timestamp` then `timestamp`).
- **Post+Collect "httpRequest is not a function"** → use `this.helpers.httpRequest` (Code node, Run Once for All
  Items); ensure the node is not in "Run Once for Each Item" mode.
- **duplicate Iris alerts after a webhook blip** → expected only on a rare partial post-failure (the local webhook
  is highly reliable); the contiguous-prefix advance prevents skips, accepts a rare re-triage.

---

## Section H — Export + cost-safe shutdown

- Export both workflows (⋯ → Download) → `JSON/falcon-alert-poller.json`, `JSON/falcon-contain.json`; sanitize
  (no inline secret / real composite_id / AID before commit).
- **Deallocate at end of session:** `az vm deallocate -g rg-soc-v2-azure-central-us -n vm-soc-v2-n8n` and
  `… -n vm-soc-v2-splunk` (state file + judge survive on the volumes; auto-resume on next start).
