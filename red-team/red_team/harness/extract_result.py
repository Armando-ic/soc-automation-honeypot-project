"""Port of the deployed n8n `Extract Result` Code node (JS_EXTRACT) to Python.

Source of truth: `JS_EXTRACT` in
`infra/honeypot/build_honeypot_triage_workflow.py` (lines 175-304 as of this
port). This must reproduce that transform byte-for-byte -- including the
`verify_body` shape (the highest-signal fidelity check the /verify endpoint
scores against), the nested Discord embed body, the Iris `alert_iocs`
extraction, and the `iris_description` template -- so the red-team harness
scores model outputs against the SAME logic the deployed `honeypot-triage`
n8n workflow runs.

Interface note: in the JS, `content` (the raw Anthropic response blocks) is
scanned for the `submit_triage_result` tool_use block, and `r = toolCall.input`.
In this port, `tool_input` IS that already-extracted `r` -- the
content-parsing / tool_use-find step (JS lines 176-178) lives upstream in
`model_client.py` (`_find_tool_use` / `classify_outcome`), not here. The JS
`if (!toolCall) throw` becomes `NoToolCall` here: a defensive assert, since
the runner only calls `extract_result` for TOOL_CALL/PARTIAL outcomes.

The defensive fill (JS `x || default`, fill-on-falsy/whitespace) MUTATES a
COPY of `tool_input` -- never the caller's dict -- and only ever fills empty
structure; it never overwrites a present, non-empty value.
"""
from __future__ import annotations

IRIS_IOC_TYPE_IDS = {"ip": 79, "domain": 20, "md5": 90, "sha1": 111, "sha256": 113}
TLP_AMBER = 2
BULLET = "•"
EMDASH = "—"

_SEVERITY_IRIS_IDS = {"low": 4, "medium": 1, "high": 5, "critical": 6}

_SCRUB_TARGETS = ("mydfir-splunk", "192.168.129.131", "vm-soc-v2-splunk")


class NoToolCall(Exception):
    """Raised when there is no usable `submit_triage_result` tool call.

    Mirrors the JS `if (!toolCall) throw new Error(...)` at JS_EXTRACT line 178,
    which fires BEFORE any defensive fill or verify_body construction. Production
    has no onError override on this node, so a no-tool-call routes straight to
    needs-human with no verify_body and no gate -- a refusal can never bypass.
    """


def _scrub_link(link: str) -> str:
    """Replace each of the three internal-host needles with x.x.x.x, FIRST
    occurrence only per needle -- matching JS `String.replace(needle, repl)`
    (single-shot, not global) rather than Python's all-occurrences `.replace`."""
    for needle in _SCRUB_TARGETS:
        link = link.replace(needle, "x.x.x.x", 1)
    return link


def _field(elem, key):
    """JS member access on a model-supplied list element: `elem.key`.

    In the deployed JS, `elem.key` yields `undefined` (never throws) whether
    `elem` is an object missing `key` OR a primitive (string/number/None). The
    port mirrors that graceful degradation with `.get()` on a dict and `None`
    on anything else -- rendering Python's `None` (str -> "None") exactly as the
    sibling iocs `.get()` code already does. These strings are display-only
    (iris_description / discord_body) and read by no gate predicate, so mirroring
    the existing non-crashing behavior matters, not the exact sentinel text."""
    return elem.get(key) if isinstance(elem, dict) else None


def _resolve_iris_type_id(ioc_type: str, value) -> int | None:
    if ioc_type == "ip":
        return IRIS_IOC_TYPE_IDS["ip"]
    if ioc_type == "domain":
        return IRIS_IOC_TYPE_IDS["domain"]
    if ioc_type == "file_hash":
        v = str(value).strip().lower()
        if len(v) == 32 and all(c in "0123456789abcdef" for c in v):
            return IRIS_IOC_TYPE_IDS["md5"]
        if len(v) == 40 and all(c in "0123456789abcdef" for c in v):
            return IRIS_IOC_TYPE_IDS["sha1"]
        if len(v) == 64 and all(c in "0123456789abcdef" for c in v):
            return IRIS_IOC_TYPE_IDS["sha256"]
    return None


def extract_result(tool_input: dict | None, ctx: dict, usage: dict | None = None) -> dict:
    """Port of JS_EXTRACT. `tool_input` is the already-extracted
    `submit_triage_result` tool_use input (the JS's `toolCall.input`); `ctx` is
    the JS's `$('Build Opus Input').item.json`; `usage` is the JS's
    `$input.first().json.usage`.

    Raises `NoToolCall` if `tool_input` is not a usable dict (defensive assert
    -- the runner only calls this for TOOL_CALL/PARTIAL outcomes, both of
    which already carry a non-None tool_input dict from model_client).
    """
    if not isinstance(tool_input, dict):
        raise NoToolCall(f"Expected submit_triage_result tool call but got: {tool_input!r}")

    # Work on a copy -- the defensive fill mutates, but never the caller's dict.
    r = dict(tool_input)

    # Defensive: Opus intermittently omits the trailing narrative field (investigation_notes).
    # Guarantee all 9 required fields are structurally present so a benign omission can't gate a
    # sound triage. Substantive checks (mitre_in_retrieved, enrichment_grounded, tactic/name/
    # severity, verdict_sourced) still run on the model's REAL values -- only empty structure is filled.
    r["schema_version"] = r.get("schema_version") or "v1"
    if not r.get("investigation_notes") or not str(r["investigation_notes"]).strip():
        r["investigation_notes"] = "No additional analyst notes provided by automated triage."
    if not r.get("alert_summary") or not str(r["alert_summary"]).strip():
        r["alert_summary"] = "Honeypot alert (no summary provided)."
    if not r.get("severity"):
        r["severity"] = "medium"
    if not r.get("severity_rationale") or not str(r["severity_rationale"]).strip():
        r["severity_rationale"] = "No rationale provided."
    r["mitre_techniques"] = r.get("mitre_techniques") if isinstance(r.get("mitre_techniques"), list) else []
    r["iocs_enriched"] = r.get("iocs_enriched") if isinstance(r.get("iocs_enriched"), list) else []
    r["recommended_actions"] = r.get("recommended_actions") if isinstance(r.get("recommended_actions"), list) else []
    # JS: `r.iocs = (r.iocs && typeof r.iocs === 'object') ? r.iocs : {}` KEEPS any
    # non-null object -- including a JS array -- and only replaces a primitive/null
    # with `{}`. Mirror `typeof === 'object'` (dict OR list), replacing only
    # primitives/None. dict(tool_input) is a SHALLOW copy, so copy a dict/list iocs
    # too before the in-place bucket fill, or we'd mutate the caller's nested value.
    raw_iocs = r.get("iocs")
    if isinstance(raw_iocs, dict):
        r["iocs"] = dict(raw_iocs)
        # Bucket-fill only runs on a dict (JS array string-index -> undefined ->
        # sets buckets on the array; a Python list can't carry string keys, and
        # the brief keeps the list as-is in verify_body.result.iocs).
        for bucket in ("ips", "domains", "file_hashes", "users", "hosts"):
            if not isinstance(r["iocs"].get(bucket), list):
                r["iocs"][bucket] = []
    elif isinstance(raw_iocs, list):
        r["iocs"] = list(raw_iocs)
    else:
        r["iocs"] = {}
        for bucket in ("ips", "domains", "file_hashes", "users", "hosts"):
            r["iocs"][bucket] = []

    usage = usage or {}
    tokens_in = usage.get("input_tokens", 0)
    tokens_out = usage.get("output_tokens", 0)

    alert_iocs = []
    for item in r["iocs_enriched"]:
        # JS `i.verdict` on a non-object element is `undefined` -> fails the
        # malicious/suspicious filter -> skipped (never throws). _field mirrors
        # that: a str/int/None element yields None here and is skipped.
        if _field(item, "verdict") not in ("malicious", "suspicious"):
            continue
        type_id = _resolve_iris_type_id(_field(item, "ioc_type"), _field(item, "value"))
        if type_id is None:
            continue
        alert_iocs.append({
            "ioc_value": _field(item, "value"),
            # JS `${item.source}: ${item.summary}` interpolates a missing field as
            # the literal "undefined" and still pushes the item -- it never throws.
            # .get() reproduces that graceful degradation (Pythonic "None" instead
            # of "undefined"); no predicate reads this string, so exact text is
            # not load-bearing, only non-crashing + still-included behavior is.
            "ioc_description": f"{_field(item, 'source')}: {_field(item, 'summary')}",
            "ioc_tlp_id": TLP_AMBER,
            "ioc_type_id": type_id,
            "ioc_tags": "soc-automation,honeypot,phase0d",
        })

    # _SEVERITY_IRIS_IDS.get needs a hashable key; a non-str (e.g. list) severity
    # would be unhashable -> TypeError. JS `{...}[r.severity]` yields undefined ->
    # `|| 2` for any non-matching key and never throws, so coalesce to the default.
    try:
        sev_id = _SEVERITY_IRIS_IDS.get(r["severity"], 2)
    except TypeError:
        sev_id = 2
    # `.get()` / _field on every model-supplied nested field: a missing key OR a
    # non-dict list element renders as None (JS "undefined") instead of raising,
    # mirroring the sibling iocs .get() degradation a few lines above.
    mitre = ", ".join(
        f"{_field(t, 'id')} ({_field(t, 'name')})" for t in r["mitre_techniques"]
    ) or "none identified"
    enriched = "\n".join(
        f"{BULLET} `{_field(i, 'value')}` {EMDASH} {str(_field(i, 'verdict')).upper()} "
        f"({_field(i, 'source')}): {_field(i, 'summary')}"
        for i in r["iocs_enriched"]
    ) or "_none_"
    actions = "\n".join(
        f"{BULLET} [{str(_field(a, 'priority')).upper()}] {_field(a, 'description')}"
        for a in r["recommended_actions"]
    ) or "_none_"

    if ctx["source"] == "falcon":
        detail_link = ctx.get("console_link") or ""
    else:
        detail_link = _scrub_link(ctx.get("results_link") or "")
    link_label = "Falcon" if ctx["source"] == "falcon" else "Splunk"
    splunk_link = detail_link  # kept for back-compat of the returned key

    iris_description = (
        f"**Summary:** {r['alert_summary']}\n"
        f"\n"
        f"**Severity:** {r['severity']} {EMDASH} {r['severity_rationale']}\n"
        f"\n"
        f"**MITRE Techniques:** {mitre}\n"
        f"\n"
        f"**Enriched IOCs:**\n"
        f"{enriched}\n"
        f"\n"
        f"**Recommended Actions:**\n"
        f"{actions}\n"
        f"\n"
        f"**Investigation Notes:**\n"
        f"{r.get('investigation_notes') or '_none_'}\n"
        f"\n"
        f"---\n"
        f"{link_label}: {detail_link}"
    )

    verify_body = {
        "result": r,
        "retrieved": ctx.get("retrieved_ids", []),
        "enrichment_results": ctx.get("enrichment_results", {}),
        "run_meta": {
            "run_id": ctx["run_id"],
            "timestamp": ctx["timestamp"],
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "latency_ms": 0,
        },
    }

    # JS: `(r.mitre_techniques && r.mitre_techniques[0]) ? `${[0].id} ${[0].name}` : 'n/a'`.
    # A non-dict first element yields undefined for .id/.name (never throws) -> _field.
    if r["mitre_techniques"]:
        first = r["mitre_techniques"][0]
        top_mitre = f"{_field(first, 'id')} {_field(first, 'name')}"
    else:
        top_mitre = "n/a"

    sev = str(r.get("severity") or "").lower()
    contain_recommended = ctx["source"] == "falcon" and sev in ("high", "critical")
    desc = f"Host **{ctx['host']}** {BULLET} src_ip `{ctx.get('src_ip') or 'n/a'}`\nMITRE: {top_mitre}\nVerifier: **passed**"
    if detail_link:
        desc += f"\n[{link_label} detection]({detail_link})"
    if contain_recommended:
        desc += f"\n⚠️ **Contain recommended** {EMDASH} run `falcon-contain` for vm-honeypot-win"
    discord_body = {"embeds": [{
        "title": f"✅ {str(r['severity']).upper()} {EMDASH} {ctx.get('search_name') or 'Honeypot alert'}",
        "description": desc,
        "color": 3066993,
    }]}

    return {
        **r,
        "alert_name": ctx.get("search_name") or "Honeypot brute force",
        "severity_iris_id": sev_id,
        "iris_description": iris_description,
        "splunk_link": splunk_link,
        "alert_iocs": alert_iocs,
        "verify_body": verify_body,
        "top_mitre": top_mitre,
        "discord_body": discord_body,
        "contain_recommended": contain_recommended,
        "source": ctx["source"],
        "console_link": ctx.get("console_link"),
        "src_ip": ctx.get("src_ip"),
        "host": ctx["host"],
    }
