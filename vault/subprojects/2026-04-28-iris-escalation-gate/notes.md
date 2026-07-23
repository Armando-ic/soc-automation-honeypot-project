---
status: complete
updated: 2026-04-29
sub_project: A2
related: [[README]], [[spec]], [[plan]], [[runbook]]
---

# Notes — Sub-project A2, Iris Escalation Gate

Working notes, gotchas, learnings, open questions discovered during build.

---

## 2026-04-28 (impl) — Phase 0 verifications

### Task 0.1 — Iris IOC type IDs captured
- Live Iris catalog has 160 IOC types; we use 5. Captured IDs:
  - `ip-src` → 79 (chosen over `ip-dst` 77 — Splunk delivers source IPs)
  - `domain` → 20
  - `md5` → 90
  - `sha1` → 111
  - `sha256` → 113
- Documented in [[../../architecture/components/dfir-iris]] under new "IOC type IDs" subsection.
- **Spec/plan placeholder values were guesses (76/20/90/113/114) and several were wrong.** Real values: 79/20/90/111/113. Plan's Task 3.1 example will need the actual numbers when the Code node body is pasted.
- **Stale endpoint reference fixed in passing:** the old vault said `/iocs/add`; the actual Iris endpoint is `/case/ioc/add`. Also surfaced that `/alerts/add` accepts `alert_iocs` natively and `/alerts/escalate/{alert_id}` is the case-promotion path A2 uses.

### Task 0.2 — Wait node behavior probe — DEFERRED
Skipping the standalone probe; will verify `$execution.resumeUrl` resolution + timeout field name inline during Phase 6 (the same execution that wires the Wait node will surface both). Plan's documented fallbacks (manual `$execution.id` URL construction; inspect `$json` shape post-resume) cover both unknowns.

### Phase 3 Code node — Unicode encoding lesson (rediscovered)

A1 ran into clipboard mojibake with em-dashes and emoji (`â€"` etc.). A2 hit it again on the first paste of the Extract Triage Result body. **Permanent fix:** in the source, use only ASCII — encode all user-visible Unicode via JS escape sequences:

- `'\u{1F7E2}'` for emoji (supplementary plane, brace syntax required)
- `'⚪'` / `'•'` / `'—'` for BMP chars (no braces)

The working file at `scratch/extract-triage-result-a2.js` (gitignored) is pure ASCII and pastes through any clipboard pathway without mangling. The JS engine resolves escapes at runtime, so Slack/Iris see the real chars.

**Generalized rule for the runbook:** whenever a Code node will display Unicode to humans (Slack, Iris, web), prefer `\u` escapes over raw Unicode literals in the source. ASCII source = clipboard-safe.

### Task 0.3 — Slack node Block Kit support — CONFIRMED (Branch A)
n8n Slack node v??? exposes Block Kit at:
- Click Slack node → **Message Type** dropdown (default `Simple Text Message`) → select **`Blocks`**
- A **`Blocks`** field appears that accepts raw JSON (Fixed/Expression toggle, Block Kit Builder link inline)
- Other Message Type options seen: `Simple Text Message`, `Blocks`, `Attachments`
- Bonus finding: **"Reply to a Message"** under Add Option carries `thread_ts` — exactly what Phase 8 thread replies need (no HTTP Request fallback for replies either)

**Decision for Phase 5+:** use native Slack nodes throughout. No `chat.postMessage` HTTP Request fallback needed.

---

## 2026-04-28 (impl) — Phase 3 Code node test

Plan Task 3.2 — smoke-test the new `Extract Triage Result` body with Test 2 (external IP / `185.220.101.42` / count=47) pinned data.

- All A1 fields preserved: yes (severity, severity_iris_id, slack_message, iris_description, splunk_link, alert_name, iocs, iocs_enriched, mitre_techniques; `recommended_actions` and `investigation_notes` correctly fall back to `_none_` in rendered strings — Claude omitted both, A1's known pattern)
- `alert_iocs` populated for external-IP test: yes, count = 1
- `alert_iocs[0].ioc_type_id`: 79 — correct live `ip-src` ID from Phase 0.1 (not the stale 76 placeholder from spec)
- `alert_iocs[0].ioc_tlp_id`: 2 (TLP:Amber); `ioc_tags`: `soc-automation,a2`; `ioc_description`: `AbuseIPDB: <summary>` (source/summary concat)
- `alert_iocs_summary` rendered correctly: yes — `• \`185.220.101.42\` (ip)`
- `iris_description` ends in raw `Splunk: <url>` (no markdown link): yes — A1 limitation fixed in passing
- `slack_message` retains Slack mrkdwn link `<url|View in Splunk>` (correct — Slack renders this; only Iris gets the raw URL)

Phase 2 changes also confirmed live in this run: Claude's `iocs_enriched[0].ioc_type` = `"ip"` (system prompt addendum took; schema enum accepted).

**State note:** v2 had no pin data when this session started — n8n's pin data did not carry over from the v1→v2 duplicate (Phase 1.2). Re-established Webhook + `Message a model` pins via one fresh end-to-end of those two nodes (Iris/Slack downstream of Extract did not fire). Pin data now lives in n8n's DB; will be captured in JSON at the next Task that exports v2 (Task 4.1).

---

## 2026-04-28 (impl) — Phase 4 Iris alert response shape + severity bug fix

### Task 4.2 — `Create Iris Alert` live test step

Body now carries `alert_iocs`; "Always Output Data" enabled; isolated Test step against live Iris (192.168.129.133) returned HTTP 200 + `status: "success"`.

Response field paths (verified live, for downstream nodes to reference):

- Alert ID: `data.alert_id` (integer, e.g. `12`, `13` from this session's runs)
- Alert UUID: `data.alert_uuid` (string)
- IOC UUIDs: `data.iocs[].ioc_uuid` (array — A2's `Escalate Iris Alert` will pass this as `iocs_import_list`)
- Per-IOC type round-trip: `data.iocs[].ioc_type.type_name` confirms type_id 79 = `ip-src` exactly as Phase 0.1 captured.

n8n expression for downstream use:

| Need | Expression |
|---|---|
| Alert ID | `{{ $('Create Iris Alert').item.json.data.alert_id }}` |
| IOC UUIDs | `{{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}` |

### Detour — A1 severity-mapping bug discovered and fixed

The first Test 2 alert (`alert_id: 12`) came back with `severity.severity_name: "Low"` despite Claude scoring `"high"`. Confirmed in Iris UI — alert is real, badge says "Low".

Root cause: A1's Code node mapped `{ low: 2, medium: 3, high: 4, critical: 5 }`, assuming linear severity IDs. Live `/manage/severities/list` shows the catalog is **non-linear**:

| `severity_id` | `severity_name` |
|---|---|
| 1 | Medium |
| 2 | Unspecified |
| 3 | Informational |
| 4 | Low |
| 5 | High |
| 6 | Critical |

A1's mapping silently understated every alert: low→Unspecified, medium→Informational, high→Low, critical→High. Bug never surfaced because A1 didn't capture the alert-creation response (the `alwaysOutputData` toggle A2 just enabled is what made it visible).

Fix landed in the same Code node (one-line change to `sevId` table, with new explanatory comment block):

```js
const sevId    = { low: 4, medium: 1, high: 5, critical: 6 }[r.severity] || 2;
```

Catalog documented in [[../../architecture/components/dfir-iris]] under new "Severity IDs" section, alongside the existing IOC type IDs section. Same lesson re-learned: **Iris ID catalogs are non-linear and deployment-specific — always capture from live, never assume.**

Verification after fix: a second Test 2 run produced `alert_id: 13` with `severity.severity_name: "High"` and `alert_severity_id: 5`. Working as intended.

The pre-fix alert #12 in Iris is left in place as a historical artifact (no need to delete; it's harmless and conveniently illustrates what the bug looked like).

**Implication for A1's runbook:** A1 documented `severity_iris_id` as derived from Claude's verdict but never validated round-trip against Iris's catalog. A2's runbook should call out the live-catalog-capture pattern as a required gate.

---

## 2026-04-28 (impl) — Phase 5.1 cross-graph expression gotcha

When rewiring `Send a message` from a direct child of `Extract Triage Result` to a downstream child of `Create Iris Alert`, the original expression `{{ $json.slack_message }}` started rendering as the literal string `"undefined"` in Slack. Cause: `$json` resolves to the *immediate* upstream node's output. Once Iris was inserted in the chain, `$json` became Iris's response — which has no `slack_message` field.

Fix: change to the cross-graph reference form:

```
{{ $('Extract Triage Result').item.json.slack_message }}
```

This pattern reaches a specific named upstream node regardless of intermediate nodes. We'll use it again in Task 5.3 (Block Kit Slack node) and Phase 8 (thread reply nodes).

**Generalized rule for the runbook:** when n8n nodes consume fields from a non-immediate upstream node, always use `$('Source Node').item.json.field`. `$json.field` is a footgun in any non-linear or multi-stage workflow — fine for two-node chains, silently wrong for anything more complex. Same family as A1's "Expression mode auto-prefixes `=`" gotcha — both are n8n syntactic surprises that fail at runtime, not validation time.

The pre-fix Slack post in #alerts (single message, body literal `"undefined"`) is a harmless audit-trail artifact; left in place.

---

## 2026-04-28 (impl) — Phase 5.2 IF strict-type-validation gotcha

The IF node's default `typeValidation: "strict"` mode rejects values whose JS type doesn't match the declared comparison type. After adding the `Has Malicious IOCs?` IF with `Number > 0`, executions failed with:

> Wrong type: '1' is a string but was expecting a number [condition 0, item 0]

Root cause: a trailing `\n` (newline) had been left in the leftValue expression field — `={{ $('Extract Triage Result').item.json.alert_iocs.length }}\n`. The newline coerced n8n's numeric result (`1`) to a string (`'1\n'`) via implicit concatenation, which strict mode then rejected.

Fix: strip the trailing whitespace from the leftValue field. Alternative workaround would be toggling "Convert types where required" ON, but that masks the cause; clean expression is preferable.

**Generalized rule for the runbook:** when typing expressions into n8n condition fields, ensure the value ends with `}}` and nothing after. The field's text editor sometimes inserts a newline on Enter — review by clicking back into the field after pasting.

---

## 2026-04-28 (impl) — Phase 5.3 native Slack node Block Kit support is a dead end

Phase 0.3 confirmed n8n Slack node v2.4 *exposes* a Block Kit JSON field via `Message Type: Blocks` → `Blocks` field. Implementation in Phase 5.3 found that the field accepts JSON input (with no error in either Expression or Fixed mode) but **n8n does not actually translate it to a `blocks` field in the outgoing Slack API request**. Slack receives only the `text` parameter and synthesizes a single `rich_text` block as fallback — buttons, dividers, action prompts never appear.

Verified via two test runs:
1. Real Block Kit JSON with cross-graph expressions and JSON.stringify-wrapped multi-line content (Expression mode): Slack response showed only the text-fallback rich_text block; expected 4 blocks (section + divider + section + actions).
2. Minimal hardcoded diagnostic — three plain blocks (text section, divider, actions block with one URL button to `http://example.com`) in Fixed mode: same result. No buttons rendered.

Slack API responses for both runs returned `ok: true` with `message.blocks` containing one auto-synthesized `rich_text` block. That confirms n8n is sending text-only requests; it isn't a Slack-side rejection.

This invalidates Phase 0.3's "Branch A confirmed" finding for the actual posting behavior. The Block Kit *configuration UI* exists; the *runtime translation* doesn't work in this version (n8n 2.4 Slack node, typeVersion 2.4 in workflow JSON).

**Decision:** abandon Branch A. Switch to the plan's documented **Branch B fallback**: HTTP Request node calling Slack's `chat.postMessage` API directly. This bypasses n8n's Slack node entirely and lets us send the `blocks` array as part of the explicit JSON body — the same approach we already use for DFIR-Iris.

Implementation steps from here:
- Replace the `Post Slack Alert + Approve/Deny` Slack node with an HTTP Request node, keeping the same name and IF-true-branch wiring.
- Use Slack credential reuse via HTTP Request's "Predefined Credential Type → Slack API" option (no need to extract the bot token).
- Body JSON includes `channel`, `text` (fallback for notifications), and `blocks` (the Block Kit array).
- Same Block Kit content as the failed Branch A attempt (section, divider, action prompt, two URL buttons), now safely embedded as a structured JSON body.

The four+ Iris alerts already created during Branch A debugging (#13, #14, #15, etc.) plus the Slack messages without buttons all stay as harmless audit-trail artifacts.

**Update Phase 0.3 finding in retrospect:** the "native Slack node + Block Kit" path looked viable based on UI exploration, but only end-to-end implementation surfaced that the field doesn't wire through. Future Phase-0-style verifications for new node types should always include a minimal end-to-end test (post a hardcoded payload, confirm Slack actually receives it as expected) — UI presence ≠ runtime functionality.

---

## 2026-04-29 (impl) — Phase 10 Tests 1-2 + the iocs_import_list saga

### Test 1 — Gate skipped: PASSED

Pinned Test 1 webhook payload (RFC1918 internal brute force — `src_ip: 192.168.129.1, count: 5, search_name: Test-Brute-Force`) via curl-to-test-webhook + repinned `Message a model` after one fresh Anthropic call.

| Check | Result |
|---|---|
| `alert_iocs` empty | ✓ `[]` |
| `alert_iocs_summary` | ✓ `"_none_"` |
| Claude triage | ✓ severity `"medium"`, sensible for low-volume internal |
| `severity_iris_id: 1` → Iris `severity_name: "Medium"` | ✓ severity mapping (Phase 4 fix) flowing through |
| Iris alert created with `iocs: []` | ✓ alert #30 |
| IF false branch took | ✓ visible on canvas |
| Slack: plain alert, NO buttons | ✓ |
| Wait For Decision NOT reached | ✓ |
| Total execution | < 30s |

### Test 2 — Approve path: PASSED (after substantial debugging — see saga below)

Pinned Test 2 webhook (`185.220.101.42` Tor exit, count: 47) + fresh Anthropic call. Final pass produced Iris alert #41 → case #10 with the IOC properly imported into the case-level threat-intel DB.

### Saga — Iris escalate body shape (4 patterns tried, 1 worked)

The plan's Task 8.1 escalate body shape (and Iris's documented OpenAPI spec) had several traps. Below is the full timeline so the next session doesn't re-discover them.

**Pattern A (plan-as-written): "Using JSON" body, quoted `{{ }}` for array.**

```json
"iocs_import_list": "{{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}"
```

Result: Iris HTTP 200, case created, **but `iocs_import_list` silently ignored** — n8n's template substitution wraps the array result in JSON-string quotes (`"[\"uuid\"]"`), which Iris parses as a string and ignores. Case-level IOC tab empty. Wrong.

**Pattern B: "Using JSON" body, unquoted `{{ }}` for array (Expression mode).**

```json
"iocs_import_list": {{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}
```

Result: n8n rejected — `{{ }}` outside string literals isn't valid JS in Expression mode (the field's mode at the time). Even in Fixed mode, n8n's static JSON validation likely rejects it.

**Pattern C: "Using JSON" body, JS object literal in Expression mode.**

```js
={
  iocs_import_list: $('...').item.json.data.iocs.map(i => i.ioc_uuid),
  ...
}
```

Result: n8n rejected with `"The value in the 'JSON Body' field is not valid JSON"` — n8n statically validates the field as JSON syntax before evaluation. JS object literals don't pass the static check.

**Pattern D: "Using JSON" body, `JSON.stringify({...})` in Expression mode.**

```js
=JSON.stringify({ iocs_import_list: ..., ... })
```

Result: same n8n static-JSON-validation rejection. The `JSON.stringify(...)` expression doesn't look like JSON at design time, so n8n rejects without ever evaluating.

**Pattern E (Fields Below): "Using Fields Below" body with each parameter as a separate field.**

Result: Iris HTTP 400 with `'NoneType' object is not iterable` — n8n's Fields Below sent the array-typed parameter as `null` to Iris (Expression-mode array result didn't survive Fields Below's stringification). Iris's escalate handler tried to iterate over null.

**Pattern F: "Raw" body type + Content-Type header + JSON.stringify expression.**

```
=JSON.stringify({ iocs_import_list: ..., ... })
```

Result: Iris HTTP 500 (Internal Server Error, generic HTML). Body shape was correct but a different bug was triggered. Initially thought to be Pattern F's fault, but direct curl with the same body shape ALSO hit either 500 or NoneType errors. Root cause was on Iris's side (see "Iris escalate handler bugs" below).

**Pattern H (final, working): Code node builds the body, HTTP Request sends as Raw.**

Inserted a `Build Escalate Body` Code node between the Switch's approve output and Escalate Iris Alert. The Code node has full JS access, builds the body object with proper types, calls `JSON.stringify()` once, returns a `escalate_body` string field plus a `escalate_body_preview` debug field. The Escalate node then uses Raw body with `={{ $json.escalate_body }}`.

```js
const ai = $('Create Iris Alert').first().json.data;
const tr = $('Extract Triage Result').first().json;

const body = {
  iocs_import_list: ai.iocs.map(i => i.ioc_uuid),
  assets_import_list: [],
  import_as_event: true,
  note: "Auto-escalated by SOC Automation A2 after analyst approval.",
  case_tags: "soc-automation,a2,auto-escalated",
  case_title: `[ALERT #${ai.alert_id}] ${tr.alert_name} — ${tr.severity}`
};

return [{ json: { escalate_body: JSON.stringify(body), escalate_body_preview: body } }];
```

Code node mode: **Run Once for All Items** (matching Extract Triage Result's pattern). Run Once for Each Item produces validation error `"A 'json' property isn't an object [item 0]"` because the array-wrapped return doesn't fit that mode.

**Result: Iris HTTP 200, case #10 created, IOC `185.220.101.42` properly imported into case-level IOC tab.** Verified visually in Iris UI with the right tags (`soc-automation, a2`) and TLP (Amber).

**Generalized rule for the runbook:** for n8n HTTP Request bodies that include arrays, objects, booleans, or numbers (non-string types), use the **Code-node-builds-body + Raw-HTTP-body** pattern. Don't rely on n8n's "Using JSON" template substitution or "Using Fields Below" type coercion — both have silent failure modes for non-string types. The Code node is debuggable (output panel shows the constructed body) and bypasses all of n8n's body field validation/stringification.

### Iris escalate handler bugs (deployment-specific, captured 2026-04-29)

While debugging via direct curl, discovered Iris's `/alerts/escalate/{alert_id}` handler has unhandled-None bugs in fields the OpenAPI spec marks optional:

- Missing `case_tags` → Python `'NoneType' object has no attribute 'split'` — handler calls `.split()` on `case_tags` without null-check
- Missing `assets_import_list` → Python `'NoneType' object is not iterable` — handler iterates over `assets_import_list` without null-check

**Both must be present in the body** (even if empty: `assets_import_list: []`, `case_tags: "anything"`). Our body always includes both, so this isn't a current blocker, but the runbook should call this out: don't trim "optional" fields from the escalate body without testing — Iris's spec/impl mismatch will silently 500.

### Test 3 — Deny path: PASSED

Same Test 2 pinned data (`185.220.101.42` Tor exit, count: 47); only the action differs — clicked ❌ Deny instead of ✅ Approve. Workflow execution at `Apr 29, 16:18:31`, succeeded in ~30s (the 30s reflects analyst click latency, not a timeout — Wait is back at 1800s).

| Check | Result |
|---|---|
| Iris alert created | ✓ alert #42 |
| Slack post with Approve/Deny buttons | ✓ |
| Wait resumed on Deny click | ✓ |
| Switch routed to `deny` output (not `approve`/timeout) | ✓ — `Reply: Denied` node fired, which is only reachable via deny |
| `Escalate Iris Alert` did NOT fire | ✓ |
| `Build Escalate Body` did NOT fire | ✓ |
| `Reply: Approved + case` / `Reply: Approved but escalate failed` did NOT fire | ✓ |
| `Reply: Denied` thread reply posted in Slack | ✓ (visible as "1 reply" on the original alert thread) |
| **No** new Iris case created from alert #42 | ✓ — alert remains in Iris's alert queue |

Fast test as expected — the deny branch had been informally exercised during Phase 8.3 testing, so this was confirmation of end-to-end behavior with the now-final workflow. No surprises.

### Test 4 — Timeout path: PASSED

Same Test 2 pinned data; Wait timeout temporarily reduced (to ~30s for fast cycle), workflow executed, **no buttons clicked**. Wait fired its timeout, the resume passed the upstream Slack-response object through (matching the Phase 6 finding — no `timedOut` field, just the upstream item), and the `Decision?` Switch routed to **Fallback** (no `query.decision === 'approve'` and no `query.decision === 'deny'`).

| Check | Result |
|---|---|
| Iris alert created | ✓ alert #43 |
| Slack post with Approve/Deny buttons | ✓ |
| Wait timed out (no click) | ✓ |
| Switch routed to **Fallback** output (not approve/deny) | ✓ — visible on canvas (1 item out of Fallback, 0 out of approve/deny) |
| `Build Escalate Body` did NOT fire | ✓ |
| `Escalate Iris Alert` did NOT fire | ✓ |
| `Reply: Approved + case` / `Reply: Approved but escalate failed` did NOT fire | ✓ |
| `Reply: Denied` did NOT fire | ✓ |
| `Reply: Timeout` thread reply posted in Slack | ✓ (visible as "1 reply" on alert thread; node shows green/1 item on canvas) |
| **No** new Iris case created from alert #43 | ✓ — alert remains in Iris's alert queue |

Validates the Phase 6 design decision that fallback (not a timed-out flag) is the correct timeout-detection mechanism — `query.decision` is simply undefined when the Wait fires its timeout, and the Switch's catch-all is the natural landing.

### Test 5 — Escalation failure (Iris VM down): PASSED

Negative-path test. Sequencing matters: Iris must be UP at workflow start (so `Create Iris Alert` succeeds and Slack posts the buttons), THEN Iris is killed while the workflow is paused on Wait, THEN Approve is clicked. This is the only way to exercise the post-Approve-but-pre-case-created failure path the runbook needs to document.

Sequence:
1. Wait timeout reset to 1800s (production value) — also serves as Phase 11 pre-flight ✓
2. Workflow executed with Iris up → `Create Iris Alert` green → Iris alert **#44** created → Slack post with Approve/Deny buttons → workflow paused on `Wait For Decision`
3. Iris VM stopped (host: 192.168.129.133)
4. Iris-down confirmed via curl: `HTTP 000` (connection failed, no response)
5. ✅ Approve clicked in Slack

Result on canvas:

| Node | State |
|---|---|
| `Decision?` Switch | approve output fired (1 item) |
| `Build Escalate Body` | ✓ green (1 item out — no Iris dependency, JS-only) |
| `Escalate Iris Alert` | routed via **Error** output (1 item Error, 0 items Success) — Continue On Fail behaved as designed |
| `Escalation Succeeded?` IF | took the false branch (Error → Reply: Approved but escalate failed) |
| `Reply: Approved but escalate failed` | ✓ green (1 item — Slack post succeeded) |
| `Reply: Approved + case` | DARK (Success branch never took) |
| `Reply: Denied` | DARK |
| `Reply: Timeout` | DARK |

Slack thread reply text (matches spec section 5d exactly):

> ❌ **Approval received but escalation failed:** The host is unreachable, perhaps the server is offline.
> Iris alert #44 remains in the alert queue. Manual escalation required.

The `<error msg>` placeholder in the spec resolved at runtime to `"The host is unreachable, perhaps the server is offline."` — n8n's HTTP node surfaces a human-readable diagnosis rather than a generic "request failed". This is the most useful error signal an analyst could get; the manual-escalation path is unambiguous.

⚠️ **Wait timeout was reset to 1800s before this test** — also satisfies Phase 11's pre-flight requirement that the exported v2 JSON ships with production timeout values, not test shortcuts. No further reset needed before cutover.

### Side artifacts from Phase 10 testing

Iris alerts #30-#44 created during Tests 1-5 and debug iterations. Iris cases #2 (early SSL-fix test), #4 (Pattern A test, no IOCs), #8/#9 (curl debug), #10 (Test 2 final pass — only legitimate case from Phase 10). All harmless audit-trail artifacts; no need to clean up.

### Phase 10 status — COMPLETE

- [x] Test 1 — gate skipped — PASSED
- [x] Test 2 — approve path — PASSED (after Pattern H fix)
- [x] Test 3 — deny path — PASSED
- [x] Test 4 — timeout path — PASSED
- [x] Test 5 — escalation failure (Iris down) — PASSED

All five gate paths verified end-to-end with pinned data. Workflow ready for Phase 11 (Splunk webhook cutover to v2).

### Post-recovery verification (after Iris restart)

Once the Iris VM came back up, ran two API queries to definitively confirm Test 3/4/5 left no residue:

```
GET /alerts/filter?alert_ids=44 → alert #44 exists with case_id=[]    ✓
GET /manage/cases/list          → highest case is #10 (from alert #41) ✓
```

No case was created from alerts #42 (Test 3 deny), #43 (Test 4 timeout), or #44 (Test 5 escalate-fail). All three remained in the alert queue exactly as the gate design intends.

### Two operational gotchas surfaced during Iris recovery

**1. Docker port-forwarding can stick broken after a hard VM stop.**

When the user brought the Iris VM back up after Test 5 (deliberate hard stop), `docker-compose ps` showed all five containers "Up" and `iriswebapp_nginx` reporting "Up (healthy)" — nginx was even successfully serving its in-container localhost healthcheck (`127.0.0.1 ... GET / HTTP/1.1 302` every 5s, visible in nginx access log). But host-level curl to `https://localhost/` hung 10s with HTTP 000, and external curl from the SOC host got TCP timeouts despite ICMP working and `ss -tulpn` showing `docker-proxy` bound to `0.0.0.0:443`.

Root cause: stale iptables NAT rules in the host network namespace from the abrupt stop. Fix:

```bash
cd ~/iris-web
sudo docker-compose down    # tears down docker network + NAT rules
sudo docker-compose up -d   # fresh network + fresh NAT rules
```

`down` does not remove volumes (no `-v` flag), so postgres data including alert #44 survived.

**Implication for runbook (Phase 12):** the standard "Iris won't come back up after VM stop" recovery is `down` then `up -d`, not just `up -d`. The "Up (healthy)" state from `compose ps` is misleading — it reflects in-container nginx healthchecks and says nothing about whether host:container port forwarding is actually working. Always confirm with a host-side curl, not just compose status.

**2. Cosmetic Unicode mangling in `Build Escalate Body` case_title.**

Iris case #10's name came back as `[ALERT #41] Test-Brute-Force-External � high` — the em-dash (`—`) in the `Build Escalate Body` Code node's case_title template literal was mangled to a replacement char somewhere between n8n's Code editor and Iris's database.

The current `Build Escalate Body` Code node uses a raw em-dash literal in the case_title template. The fix is to apply the rule already documented in this notes file under "Phase 3 Code node — Unicode encoding lesson (rediscovered)": replace the literal em-dash with the JS Unicode escape sequence (backslash, lowercase u, 2014). See the existing escape reference table earlier in this file for the BMP-vs-supplementary-plane variants.

Cosmetic only — the case still works; only the title display is affected. Defer fix to a Phase 12 cleanup commit. The Phase 0/3 generalized rule ("ASCII source, escape all user-visible Unicode in JS source") was originally discovered while building `Extract Triage Result`; `Build Escalate Body` was added later in Phase 10's Pattern H saga and didn't get the same treatment.

(Meta note: writing this section also surfaced that the SAME mangling can happen at Claude Code's tool-call JSON layer — the `—` escape gets interpreted into a literal em-dash before reaching the file. Workaround when documenting: describe the escape by rule reference rather than embedding the literal escape sequence inline; or double-escape the backslash in the tool input. The lesson's scope expands: Unicode escapes can be silently re-interpreted at any tool/transport boundary, not just clipboard paste.)

---

## 2026-04-29 (impl) — Phase 11 cutover + e2e PASSED

### Phase 11.1 — Splunk webhook cutover

Webhook GUIDs differed between v1 and v2 (n8n didn't preserve GUID on workflow duplicate in Phase 1.2):

| Workflow | Production webhook URL |
|---|---|
| v1 (legacy) | `http://192.168.129.132:5678/webhook/9ccbefed-5e8a-4f16-87f4-12128ffa89ae` |
| v2 (A2) | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` |

Sequence executed:
1. Activated `SOC Triage v2` in n8n
2. Deactivated `SOC Triage v1 (legacy)` in n8n
3. Updated Splunk's `Test-Brute-Force` saved-search webhook URL to v2's

Cutover window was safe because the saved search was already disabled from Phase 10 testing — no in-flight alerts to lose.

**Generalized rule for the runbook:** when n8n duplicates a workflow, do not assume the webhook GUID is preserved. Compare both before activating to know whether Splunk needs a URL update or not. (n8n's behavior may differ across versions.)

### Phase 11.2 — End-to-end with real Splunk alert: PASSED ×2

#### The Splunk saved-search edit gotcha

Plan recommended appending `| eval src_ip="..."` to the `Test-Brute-Force` saved search to force an external IP through the gate-fires path. Both append-after-stats AND a duplicate-then-edit attempt **silently dropped the eval clause** when saved — Splunk's saved-alert form normalizer rejects post-stats modifications.

**Workaround that worked:** Save As Alert from the Search & Reporting search bar with the eval inlined inside the pipeline (before stats). Created a new alert `Test-Brute-Force-External-Spoofed` with:

```
index="mydfir-project" EventCode=4625
| eval src_ip="185.220.101.42"
| stats count by _time, ComputerName, user, src_ip
```

The new alert pointed at v2's production webhook URL.

**Generalized rule for the runbook:** for Splunk saved-search SPL modifications that include `eval` or other transformations affecting fields, do them in the Search & Reporting search bar and "Save As Alert" rather than editing the existing saved search through the Settings UI — the Settings-side edit form has hidden validation that strips post-stats modifications.

#### What ran

The Splunk saved search fired on its 1-minute cron twice; both runs went through the gate end-to-end and were Approved by the analyst.

| | Run 1 | Run 2 |
|---|---|---|
| Splunk → n8n delay | ~60s (one cron tick) | ~60s |
| n8n execution duration | ~32s (analyst click latency) | ~32s |
| Iris alert created | **#47** | **#48** |
| Slack post with buttons | ✓ | ✓ |
| Analyst clicked ✅ Approve | ✓ | ✓ |
| Iris case escalated | **#11** | **#12** |
| Case-level IOC (185.220.101.42, ip-src, soc-automation+a2 tags, TLP:Amber) | ✓ | ✓ |
| Reply: Approved + case Slack thread reply | ✓ | ✓ |

All A2 architectural deliverables validated against real production traffic:
- Splunk webhook → v2 (cutover GUID change works)
- Real Anthropic API call (no pinning) — schema-compliant structured output with all fields populated correctly (ioc_type=ip surfaced from the system prompt addendum)
- Real AbuseIPDB enrichment of 185.220.101.42 — MALICIOUS, confidence 91/100, full Tor exit context surfaced into the Slack message
- Iris alert created with `alert_iocs` populated → API response captured by n8n → IOC UUIDs flowed through to escalate
- Gate fired (`Has Malicious IOCs?` IF → true, because filtered list non-empty)
- Slack Block Kit message rendered with two URL buttons (signed `$execution.resumeUrl` resolved at Slack-post time per Phase 6 finding)
- Wait For Decision held the workflow until the analyst's button click resumed it via the signed webhook
- Decision Switch routed to approve based on `query.decision==='approve'` (per Phase 6 finding, not the spec's original `timedOut` design)
- Build Escalate Body Code node + Raw HTTP escalate (Pattern H from Phase 10) succeeded against live Iris
- Escalation Succeeded? IF took the success branch
- Reply: Approved + case Slack thread reply posted with the case link

#### Em-dash bug confirmed in production traffic

Cases #11 and #12 both came back with case names `... � high` instead of `... — high` — the same `Build Escalate Body` em-dash mangling that hit case #10 in Test 2. Three production-real cases now demonstrate the bug; deferring the fix to Phase 12 cleanup is acceptable but the fix should ship before A2 closes.

### Phase 11 status — COMPLETE

- [x] Phase 11.1 — webhook cutover (v2 active, v1 inactive, Splunk URL updated)
- [x] Phase 11.2 — end-to-end with real Splunk alert (×2 runs, both PASSED full Approve path)

Splunk saved search disabled after the e2e (otherwise it would have kept producing cases on every cron tick).

### Em-dash bug — Phase 12 follow-up: not reproducing (2026-04-30)

While verifying the Phase 12 e2e (case #13 from alert #50, full Approve path against the as-shipped v2 JSON), the cases list view in Iris UI showed cases #10, #11, #12, and #13 all rendering clean em-dashes in their case_titles — `[ALERT #50] Test-Brute-Force-External-Spoofed — high`. The Unicode replacement glyph reported during Phase 11 against cases #11/#12 did not reproduce.

The repo JSON was already encoding the em-dash as a `—` JS escape (verified at byte level — the file contains `\\u2014` in JSON, which parses to `—` in the JS source string, which JS resolves to U+2014 at runtime). No edit to the JSON was needed for Phase 12 closure.

Possible explanations for the original observation: (a) transient display issue on the original Iris UI surface (e.g., a different page that wasn't using a font with em-dash glyph coverage at the time); (b) misread of glyphs at a low resolution / wrong-font scenario; (c) intermediate n8n/Iris state that has since changed. None definitive.

**Decision:** preserve the historical observation here, document the not-reproducing finding in [[runbook]]'s "Em-dash mangling (historical, not currently reproducing)" section, and ship A2 without a source-level ASCII fix. If the bug recurs, the runbook section has the diagnostic context.

The Phase 0/3 Unicode encoding rule (ASCII source + `\u` escapes) is still a good practice for clipboard-paste hygiene into n8n's Code editor, regardless of this specific bug's reproduction status.

A2's success criteria from the spec:

| # | Criterion | Status |
|---|---|---|
| 1 | All 5 pinned tests pass | ✓ Phase 10 |
| 2 | E2E with real Splunk alert succeeds for Approve path | ✓ Phase 11.2 |
| 3 | Iris cases created from approved alerts; case-level IOC database populated | ✓ Phase 11.2 (cases #11 #12) |
| 4 | Slack thread shows full audit trail | ✓ |
| 5 | URL buttons render and are clickable from LAN browser | ✓ |
| 6 | Timeout fires correctly at 30 min | ✓ Phase 10 Test 4 (verified at 30s test value; production value 1800s confirmed by inspection) |
| 7 | Negative-path test (escalation failure) produces expected message | ✓ Phase 10 Test 5 |
| 8 | runbook.md covers deploy / rollback / verify / debug | ⏳ Phase 12 |
| 9 | notes.md captures gotchas | ✓ (this file) |
| 10 | ADR for ioc_type schema enhancement | ⏳ Phase 12 |
| 11 | Log entry at vault root marks A2 complete | ⏳ Phase 12 |
| 12 | Iris IOC type ID catalog in dfir-iris.md | ✓ Phase 0.1 |

Remaining: Phase 12 documentation closure.

---

## 2026-04-29 (impl) — Phase 6 verified + Phase 0.2 answered live

Three concrete findings, one critical, plus Phase 0.2's deferred questions all answered against a real Wait node.

### 1. CRITICAL — n8n Wait webhooks require a signed token

The plan's documented manual fallback URL form `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}?decision=...` **does not work** in this n8n version. Hitting that URL returns `{"error": "Invalid token"}`. n8n's Wait node generates resume URLs of the form:

```
http://192.168.129.132:5678/webhook-waiting/<execution_id>?signature=<token>
```

The `signature` query parameter is computed from execution data using a server secret — it's unguessable and cannot be reconstructed manually.

**Fix:** Slack button URLs must use `{{ $execution.resumeUrl }}` (which n8n populates with the full signed URL during expression resolution, even in nodes BEFORE the Wait). Append `&decision=approve|deny` (using `&` not `?`, since the URL already has `?signature=...`):

```
{{ $execution.resumeUrl }}&decision=approve
{{ $execution.resumeUrl }}&decision=deny
```

This was committed via the Phase 6 bundle alongside the Wait node addition.

**Side benefit (security):** the original spec accepted "anyone with LAN access + the resume URL can approve" as the threat model. With signed URLs, only someone who already received the Slack message can approve — Slack-mediated authorization for free. A2.5 (signed Slack interactivity) gets a smaller scope as a result.

### 2. Phase 0.2 question 1: `$execution.resumeUrl` resolution timing

Confirmed: **`$execution.resumeUrl` populates correctly in the Slack node, before the Wait node runs.** Resolved value at Slack-post time matched the URL n8n's Wait node listened on. Spec section 5b's open question is closed.

### 3. Phase 0.2 question 2: Wait node timeout-result shape — the surprise

Spec assumed `$json.timedOut === true` would be the timeout indicator. **That field does not exist.** The Wait node has TWO distinct output shapes depending on what triggered the resume:

| Case | Wait node output |
|---|---|
| **Click (webhook hit)** | `{ headers, params, query: { signature, decision }, body, webhookUrl, executionMode }` — n8n replaces the item with the resume request's data |
| **Timeout** | Upstream item passes through **unchanged** (the Slack node's `chat.postMessage` response in our case) — no `timedOut` field, no special marker |

Verified live: timeout execution #71 (Wait time set to 30s for the test) completed in 30.329s; Wait node's OUTPUT panel showed the upstream Slack response object, identical to its INPUT panel.

**Implication for Phase 7's `Decision?` Switch design:** branch on **presence/value of `$json.query.decision`**, not on `$json.timedOut`:

- `$json.query.decision === 'approve'` → escalate sub-flow
- `$json.query.decision === 'deny'` → deny reply
- otherwise (undefined when timeout passes through Slack data, or any malformed query) → timeout reply

The original spec section 6c table entries `timeout: $json.timedOut === true` and `(fallback): malformed query → Deny` collapse into a single defensive design where any non-`approve`/non-`deny` value (including undefined-on-timeout) routes to the timeout reply. Cleaner than the spec's three-way + fallback.

### 4. Phase 0.2 question 3: Wait node "Respond Immediately" + custom HTML response — partial

Wait node's **Respond mode = Immediately** is set correctly. The configured `responseData` (HTML page) and `responseHeaders` (Content-Type: text/html) are persisted in the workflow JSON. **However, the response body sent to the analyst's browser is `{"message":"Workflow was started"}`, not our HTML page.** This appears to be a behavior of n8n's Wait node where `responseData`/`responseHeaders` only apply to certain Webhook trigger configurations, not to resume-webhook responses.

**Decision:** defer to a polish task. The functional behavior is fine — workflow resumes correctly; the analyst sees a one-line JSON message for ~1 second before closing the tab; the Slack thread reply (Phase 8) is the authoritative outcome surface. If we later want the pretty page, options are:
- Add a Respond to Webhook node downstream of Wait (probably) — requires changing Wait's Respond mode to "Use Respond Node"
- Accept the JSON response as a known limitation

Captured as a `runbook.md`-worthy known limitation when we get to Phase 12.

### 5. Side observation — Slack interactivity warning on URL buttons

Slack shows a small ⚠️ "This app is not configured to handle interactive responses. Please configure interactivity URL for this app under the app config page." warning next to URL buttons. This is benign — Slack flags `actions` block buttons as interactive elements expecting a Slack interactivity webhook, but URL-only clicks (our pattern) work fine without one. The warning can be eliminated by switching to a different block representation (e.g., a section with mrkdwn links instead of a buttons actions block), at the cost of styled buttons. Acceptable for A2; revisit in A2.5.

### 6. Side bookkeeping

The dev-cycle timeout (30 seconds) was reset to 30 minutes (1800 seconds) before exporting v2 JSON. Iris alerts created during Phase 6 testing (#16-#20+) and corresponding Slack posts in #alerts are harmless audit-trail artifacts.

---

## 2026-04-28

- Brainstorm completed; design approved across 7 sections (summary/goal/scope/approach, topology, IOC selection + payload, Iris HTTP calls, Slack message + URL buttons, Wait/Resume + branching, error handling/testing/success criteria).
- Key architectural decisions captured in [[spec]]:
  - Pattern Y: modify A1's `/alerts/add` to carry `alert_iocs`; gate fires on the `/alerts/escalate/{alert_id}` call (alert→case escalation as the gated action).
  - Plumbing: Slack URL buttons → analyst's LAN browser → n8n Wait/Resume webhook (no public tunnel, no Slack interactivity webhook).
  - Source of IOCs to push: `iocs_enriched` filtered to `verdict ∈ {malicious, suspicious}`.
  - Gate trigger: fire only when filtered list is non-empty; otherwise skip (Test 1's path).
  - Timeout: 30 minutes, treated as Deny.
  - Schema: additive `ioc_type` field on `iocs_enriched` items (still v1; ADR to be written).
- Validated against the actual DFIR-Iris OpenAPI spec rather than the vault's component-page summary (which had `/iocs/add` instead of the actual `/case/ioc/add`). The OpenAPI spec is at [`JSON/IRIS-2.0.4-OpenAPI-specification.json`](../../../JSON/IRIS-2.0.4-OpenAPI-specification.json).
- Open verifications for Phase 0 of the implementation plan:
  - `$execution.resumeUrl` resolution timing in pre-Wait nodes
  - Wait node timeout-result field name (likely `$json.timedOut`)
  - Wait node "Respond Immediately" mode behavior
  - Iris IOC type ID catalog (`curl /manage/ioc-types/list`)
  - n8n Slack node Block Kit JSON acceptance
