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
    # dict(tool_input) is a SHALLOW copy -- r["iocs"] would still be the caller's own
    # dict object. Copy it too before filling missing buckets in place, or we'd mutate
    # the caller's nested dict even though the top-level dict is "copied".
    r["iocs"] = dict(r["iocs"]) if isinstance(r.get("iocs"), dict) else {}
    for bucket in ("ips", "domains", "file_hashes", "users", "hosts"):
        if not isinstance(r["iocs"].get(bucket), list):
            r["iocs"][bucket] = []

    usage = usage or {}
    tokens_in = usage.get("input_tokens", 0)
    tokens_out = usage.get("output_tokens", 0)

    alert_iocs = []
    for item in r["iocs_enriched"]:
        if item.get("verdict") not in ("malicious", "suspicious"):
            continue
        type_id = _resolve_iris_type_id(item.get("ioc_type"), item.get("value"))
        if type_id is None:
            continue
        alert_iocs.append({
            "ioc_value": item["value"],
            "ioc_description": f"{item['source']}: {item['summary']}",
            "ioc_tlp_id": TLP_AMBER,
            "ioc_type_id": type_id,
            "ioc_tags": "soc-automation,honeypot,phase0d",
        })

    sev_id = _SEVERITY_IRIS_IDS.get(r["severity"], 2)
    mitre = ", ".join(f"{t['id']} ({t['name']})" for t in r["mitre_techniques"]) or "none identified"
    enriched = "\n".join(
        f"{BULLET} `{i['value']}` {EMDASH} {str(i['verdict']).upper()} ({i['source']}): {i['summary']}"
        for i in r["iocs_enriched"]
    ) or "_none_"
    actions = "\n".join(
        f"{BULLET} [{str(a['priority']).upper()}] {a['description']}"
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

    top_mitre = (
        f"{r['mitre_techniques'][0]['id']} {r['mitre_techniques'][0]['name']}"
        if r["mitre_techniques"] else "n/a"
    )

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
