# fixtures/envelopes

Hand-authored Splunk `output_mode=json` search-job results envelopes, one per
v1 catalog query (see `splunk_investigator/catalog.py`). Each file mirrors the
shape `service.jobs.create(...).results(output_mode="json")` returns from a
live Splunk instance:

```json
{"preview": false, "messages": [], "fields": [...], "results": [{...}]}
```

All `results[].*` field values are strings, matching how Splunk actually
serializes `output_mode=json` (e.g. `"success_count": "3"`, never a bare
`3`). This is a load-bearing detail: `parse_envelope` never coerces values,
so a fixture with a real int here would be lying about the wire format.

These are **record-once reference fixtures**, hand-authored from the known
SPL templates in `catalog.py`, not a live capture. Task 16 validates them
against a real splunklib capture (a read-only `| head` against the honeypot
index) and a fixture-diff guard will flag drift if the live shape changes
(new field, renamed field, different message text for truncation, etc.).
Until that validation lands, treat these as "best guess at the live shape,"
not "verified against production."

## Files

- `logon_outcomes_for_ip.json` -- `logon_outcomes_for_ip` query (success/fail counts for a source IP).
- `processes_by_user.json` -- `processes_by_user` query (Sysmon process-creation rows for a user on a host).
- `repeat_offender.json` -- `repeat_offender` query (first/last-seen history for a source IP).
- `user_targets_for_ip.json` -- `user_targets_for_ip` query (distinct target-account count for a source IP).
- `encoded_powershell_on_host.json` -- `encoded_powershell_on_host` query (EncodedCommand usage count on a host).
