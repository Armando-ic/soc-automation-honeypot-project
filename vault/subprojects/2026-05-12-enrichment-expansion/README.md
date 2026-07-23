---
status: stub-awaiting-brainstorm
updated: 2026-05-12
related: [[../../architecture/components/n8n]], [[../2026-04-27-structured-outputs/spec]], [[../../decisions/0007-remove-slack-iris-native-gate]]
---

# A3 — Enrichment expansion (working title)

## Status

**Stub.** This sub-project is parked for future work. No spec, plan, or runbook yet.
Per vault convention (`CLAUDE.md` "Don't write a sub-project spec without going through the brainstorming skill first"), the spec will be written via the brainstorming skill when this sub-project is opened.

## Intent

Expand the n8n triage pipeline's IOC enrichment surface beyond the current AbuseIPDB (IP) and VirusTotal (file hash) pair. Add 2–3 new sources that cover IOC categories the workflow currently lacks (URLs, domain reputation, IP geo/proxy/VPN signals) or that strengthen coverage of existing categories with second-opinion data.

## Why this exists as a sub-project

Surfaced 2026-05-12 during the n8n + IRIS rebuild conversation. User's browser bookmarks contain a rich list of SOC analyst tools (URLhaus, urlscan.io, ANY.RUN, MetaDefender, IP2Location, Scamalytics, vpnapi.io, CyberChef, etc.). The temptation was to add several of them during the rebuild. Captured here instead so the D1 freeze isn't blown up by enrichment scope creep.

## Candidate enrichments (initial brainstorm seed — not yet a decision)

Scored on (a) API availability, (b) coverage of an IOC category n8n doesn't currently touch, (c) free-tier sufficiency for a lab.

| Tool | API | New IOC coverage | Free tier? |
|---|---|---|---|
| **urlscan.io** | Yes | URL scanning, screenshots, domain enrichment | Yes (rate-limited) |
| **URLhaus** | Yes (abuse.ch) | URL malware blocklist | Yes (open) |
| **IP2Location** | Yes | IP geolocation + proxy/VPN flag | Yes (limited) |
| **vpnapi.io** | Yes | IP VPN/Tor/proxy detection | Yes (1000/day) |
| **MetaDefender Cloud** | Yes | Multi-AV file scanning (second opinion to VT) | Yes (limited) |
| **ANY.RUN** | Yes | Dynamic sandbox detonation | Mostly paid |
| **Scamalytics** | Yes | IP fraud-risk scoring | Mostly paid |

Likely top picks when brainstorm opens: **urlscan.io + URLhaus + IP2Location** — covers URL, domain, and IP-context surfaces n8n currently has no enrichment for. ANY.RUN and Scamalytics deferred to a later sub-project unless free-tier coverage improves.

## Prerequisites before this sub-project opens

- **D1 freeze complete** (`subprojects/2026-04-30-detection-foundations` → frozen).
- **SOC-Triage-v3.json** (Slack-removed, IRIS-native gate per ADR 0007) is the workflow baseline this builds on.
- IRIS, n8n, and Splunk all back to operational state post-rebuild.

## Things to think about in the brainstorm (when opened)

- **IOC type schema impact.** Current A1 schema (`ioc` | `domain` | `file_hash`) covers IP/domain/hash. URL is currently not a distinct IOC type — should it become one? If yes, this is a schema-version bump conversation (ADR-worthy, similar to 0005).
- **Where in the workflow do enrichments fire?** As parallel Claude-callable tools (current pattern), or as deterministic pre-Claude lookups whose results enter Claude's context? Or both? Decision affects token cost, latency, and determinism.
- **Rate-limit handling.** Free tiers have daily caps. Workflow needs graceful degradation when an enrichment returns 429 — log + continue, don't fail the whole triage.
- **Credential management.** Each new tool = new API key in `SOC-Automation-Project.md` (gitignored). At 5+ keys this starts wanting a real secrets approach (Vault, doppler, even .env on the n8n VM). Worth discussing as part of A3 or in a follow-up.
- **IOC-routing on type.** Now that we have `ioc_type`, we can route IPs to AbuseIPDB+IP2Location+vpnapi, hashes to VT+MetaDefender, URLs to URLhaus+urlscan, domains to urlscan+whois. Multi-source-per-type, fan-out per IOC type.
- **CyberChef.** Not an API. Could be replicated as n8n Code nodes for specific recipes (base64-decode-then-detect, encoded-PowerShell unwrap). Tempting because D1's T1059.001 detection deals with base64-encoded payloads. Could be its own narrower sub-project.

## Out of scope for this sub-project

- Re-introducing Slack or other chat-platform notification (separate decision; ADR 0007 is the canonical decision against doing this now).
- Microsoft Sentinel / Azure pivot work (the user's stated next direction post-D1-freeze).
- Splunk-side detection expansion (would be its own D-series sub-project).

## Successor relationships

- Comes after the D1 freeze closes.
- Independent of the Microsoft pivot — can run before or after that, depending on user priority.
- Could spawn follow-up sub-projects: a CyberChef-recipe-as-Code-node sub-project; a secrets-management refactor sub-project.

## How to open this sub-project

1. Confirm prerequisites (D1 frozen, v3 workflow stable).
2. Invoke the brainstorming skill against the candidate tools list above.
3. Pick 2–3 winners; write `spec.md`.
4. User approval → `plan.md` → implementation → `runbook.md` + `notes.md`.
5. Update this README's status frontmatter from `stub-awaiting-brainstorm` to `in-progress` when started.
