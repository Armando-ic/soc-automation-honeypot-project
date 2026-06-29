# Falcon Alerts v2 — field map CONFIRMED on us-2 (0D-2 §10 pre-build checks, 2026-06-29)

Confirmed against a live `GET /alerts/queries/alerts/v2` + `POST /alerts/entities/alerts/v2` on tenant **us-2**
(from a LOCAL trusted machine, not the honeypot). **Supersedes** the `[TEMPLATE]` guesses in
`crowdstrike-api-notes.md` §4 and the simplified JSON in `falcon-validation.md` for the fields 0D-2 depends on —
several of those labels were wrong. These pinned facts drive `grounding_service/falcon.py` + the
`falcon-alert-poller` FQL.

> Sanitized: `composite_id`/`origin_cid` (= the **CID**) and the AID are redacted to first/last 4. Full AID lives
> ONLY in gitignored `Personal/honeypot-vm-creds.txt` + the VM's gitignored `grounding-service/.env`
> (`FALCON_PINNED_AID`).

## The four blocking checks — resolved

| Question | Confirmed answer |
|---|---|
| **Timestamp field** | The returned object has **`timestamp`** + **`updated_timestamp`** — there is **no `created`** field (the 0B doc mislabeled it). **`created_timestamp`** works as the **FQL sort/filter key** but was **not** present on the hydrated EICAR object. → **FQL key = `created_timestamp`; watermark read = `created_timestamp` then fall back to `timestamp`** (`falcon.py` `TS_READ_FIELDS`, `alert_created()`). Since `timestamp ≤ created_timestamp`, a watermark read from `timestamp` only ever *re-pulls* (deduped by the seen-set), never skips. |
| **Host-scope filter** | ✅ **Filterable** — `filter=device.hostname:'vm-honeypot-win'` returns the host's alerts. The poller scopes to it. |
| **Attacker-source-IP field** | **`source_ips`** (a JSON **array**). Empty on behavioral Execution alerts (→ empty-IOC guard). Not yet observed populated — no `tactic:'Credential Access'` alert exists in the tenant yet (the honeypot's Falcon detections are behavioral Execution, e.g. T1204). `falcon.py` `IP_FIELDS = (source_ips, external_ip, local_ip, src_ip)`, first public IP wins; default `""`. **Re-confirm against a populated alert when one appears (Task 11).** |
| **Console deep-link** | Default `https://falcon.us-2.crowdstrike.com/activity-v2/detections/{composite_id}` (`CONSOLE_LINK_TEMPLATE`). ⚠️ **Cosmetic / unconfirmed** — pending a real per-detection URL from the console; the link is only a clickable convenience in the Iris/Discord notice. |

## Other schema facts that corrected the code

- **`composite_id` is NOT a returned field.** Reconstruct it as **`origin_cid` + `:` + `id`** (`composite_id_of()`).
  Example shape: `<cid>:ind:<aid>:<process-pattern-id>` (redacted: `306e…0772:ind:9134…5865:…995344`).
- **No top-level `filename`/`cmdline`.** Use **`name`** (the detection name, e.g. `EICARTestFileWrittenWin`) +
  **`sha256`/`md5`** for the `alert_text`. Falcon emits **all-zero `sha1`/`sha256` placeholders** — skip them
  (`_ZERO_HASH`). `parent_details` carries the real parent process cmdline/filename/sha256 (not surfaced in MVP).
- Confirmed present + used: `severity_name`, `tactic`, `technique`, `technique_id`, `user_name`,
  `pattern_disposition` (+ `pattern_disposition_details` all-false = detect-only), `prevention_policy_name`
  (`honeypot-detect-only`), `scenario`, `objective`, `status`.

## Pinned constants now in `falcon.py`

```python
TS_READ_FIELDS = ("created_timestamp", "timestamp")              # watermark read (FQL key = created_timestamp)
IP_FIELDS = ("source_ips", "external_ip", "local_ip", "src_ip")  # source_ips is an array
HOST_DEFAULT = "vm-honeypot-win"
CONSOLE_LINK_TEMPLATE = "https://falcon.us-2.crowdstrike.com/activity-v2/detections/{composite_id}"
```

## Full key list of a real us-2 alert (sanitized — the EICAR behavioral detection)

```
global_prevalence, host_names[], id (ind:<aid>:…), indicator_id, ioc_context[], local_prevalence,
local_process_id, logon_domain (vm-honeypot-win), md5, mitre_attack[], name (EICARTestFileWrittenWin),
objective, origin_cid (=CID), parent_details{cmdline,filename,sha256,user_name,…}, parent_process_id,
pattern_disposition (0), pattern_disposition_description, pattern_disposition_details{… all False},
pattern_id, platform (Windows), poly_id, prevention_policy_id, prevention_policy_name (honeypot-detect-only),
priority_details, priority_value (10), process_id, process_start_time, product (epp), scenario (known_malware),
seconds_to_resolved, seconds_to_triaged, severity (10), severity_name (Informational), sha1 (zero-placeholder),
sha256, show_in_ui, source_hosts[], source_ips[], source_products[], source_vendors[], status (new),
tactic (Execution), tactic_id (TA0002), technique (User Execution), technique_id (T1204),
template_instance_id, timestamp, tree_id, tree_root, triggering_process_graph_id, type (ldt),
updated_timestamp, user_id (SID), user_name, user_names[]
```
