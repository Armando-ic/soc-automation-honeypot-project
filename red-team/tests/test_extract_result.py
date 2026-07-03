import pytest

from red_team.harness.extract_result import extract_result, NoToolCall
from tests.conftest import load_snapshot


def _ctx_from(snap):
    boi = snap["build_opus_input_output"]
    return {
        "source": boi["source"], "run_id": boi["run_id"], "timestamp": boi["timestamp"],
        "search_name": boi["search_name"], "host": boi["host"], "src_ip": boi["src_ip"],
        "console_link": boi.get("console_link", ""), "results_link": boi.get("results_link", ""),
        "retrieved_ids": boi["retrieved_ids"], "enrichment_results": boi["enrichment_results"],
    }


def test_extract_result_verify_body_matches_snapshot():
    snap = load_snapshot("splunk_baseline")
    out = extract_result(snap["opus_tool_input"], _ctx_from(snap), usage=snap["opus_usage"])
    assert out["verify_body"] == snap["extract_result_output"]["verify_body"]


def test_extract_result_discord_is_nested_and_iocs_match():
    snap = load_snapshot("splunk_baseline")
    out = extract_result(snap["opus_tool_input"], _ctx_from(snap), usage=snap["opus_usage"])
    assert out["discord_body"] == snap["extract_result_output"]["discord_body"]
    assert out["discord_body"]["embeds"][0]["color"] == 3066993
    assert out["alert_iocs"] == snap["extract_result_output"]["alert_iocs"]


def test_contain_recommended_false_on_splunk():
    snap = load_snapshot("splunk_baseline")
    out = extract_result(snap["opus_tool_input"], _ctx_from(snap), usage=snap["opus_usage"])
    assert out["contain_recommended"] is False


@pytest.mark.parametrize(
    "needle",
    ["mydfir-splunk", "192.168.129.131", "vm-soc-v2-splunk"],
)
def test_scrub_replaces_first_occurrence_only(needle):
    from red_team.harness.extract_result import _scrub_link  # helper the port factors out
    link = f"http://{needle}/app?ref={needle}"
    assert _scrub_link(link) == f"http://x.x.x.x/app?ref={needle}"


def test_alert_iocs_missing_source_and_summary_degrades_gracefully():
    # A filter-passing iocs_enriched item (malicious verdict + resolvable ioc_type)
    # that is MISSING source/summary must NOT crash extract_result -- matching the
    # JS, which interpolates missing fields as the literal "undefined" and still
    # pushes the item into alert_iocs. Direct key indexing (item['source']) would
    # raise KeyError here; the port must use .get() instead.
    tool_input = {
        "schema_version": "v1", "alert_summary": "s", "severity": "low",
        "severity_rationale": "r", "mitre_techniques": [],
        "iocs_enriched": [
            {"verdict": "malicious", "ioc_type": "ip", "value": "10.0.0.1"},
        ],
        "recommended_actions": [], "investigation_notes": "n",
        "iocs": {},
    }
    ctx = {
        "source": "splunk", "run_id": "r1", "timestamp": "t1", "search_name": "s",
        "host": "h", "src_ip": "i", "console_link": "", "results_link": "",
        "retrieved_ids": [], "enrichment_results": {},
    }
    out = extract_result(tool_input, ctx, usage={"input_tokens": 1, "output_tokens": 2})
    assert len(out["alert_iocs"]) == 1
    ioc = out["alert_iocs"][0]
    assert ioc["ioc_value"] == "10.0.0.1"
    assert ioc["ioc_type_id"] == 79
    assert isinstance(ioc["ioc_description"], str)


def _adversarial_ctx():
    return {
        "source": "splunk", "run_id": "r1", "timestamp": "t1", "search_name": "s",
        "host": "h", "src_ip": "i", "console_link": "", "results_link": "",
        "retrieved_ids": [], "enrichment_results": {},
    }


def _min_tool_input(**overrides):
    ti = {
        "schema_version": "v1", "alert_summary": "s", "severity": "low",
        "severity_rationale": "r", "mitre_techniques": [], "iocs_enriched": [],
        "recommended_actions": [], "investigation_notes": "n", "iocs": {},
    }
    ti.update(overrides)
    return ti


def test_nameless_mitre_technique_does_not_crash():
    # C1: a model tool call that omits mitre_techniques[].name must NOT raise --
    # the deployed JS renders the missing key as "undefined" (never throws). The
    # port must degrade via .get() and still build a full result.
    ti = _min_tool_input(mitre_techniques=[{"id": "T1110.001", "tactic": "credential-access"}])
    out = extract_result(ti, _adversarial_ctx(), usage={"input_tokens": 1, "output_tokens": 2})
    assert "T1110.001" in out["iris_description"]         # degraded string still rendered
    assert out["top_mitre"].startswith("T1110.001 ")      # name -> None, no crash


def test_descriptionless_action_does_not_crash():
    # C1: an action with priority but no description must NOT raise (JS a.description
    # -> undefined).
    ti = _min_tool_input(recommended_actions=[{"priority": "high"}])
    out = extract_result(ti, _adversarial_ctx(), usage={"input_tokens": 1, "output_tokens": 2})
    assert "[HIGH]" in out["iris_description"]             # priority upper-cased, no crash


def test_non_dict_list_elements_do_not_crash():
    # C1/I1: schema-shaped-but-adversarial output whose list fields hold non-dict
    # elements (str/int/None) must flow through extract_result with NO exception --
    # JS member access on a primitive yields undefined and never throws.
    ti = _min_tool_input(
        mitre_techniques=["T1110"],
        recommended_actions=["x"],
        iocs_enriched=["x"],
    )
    out = extract_result(ti, _adversarial_ctx(), usage={"input_tokens": 1, "output_tokens": 2})
    # No exception; the degraded strings still render, alert_iocs skips the
    # non-dict enriched element (its verdict is undefined -> not malicious).
    # A non-dict element's field access is undefined (JS) / None (port), so
    # top_mitre degrades to "None None" -- byte-parity with JS "undefined undefined".
    assert isinstance(out["iris_description"], str)
    assert out["alert_iocs"] == []
    assert out["top_mitre"] == "None None"


def test_non_dict_iocs_enriched_int_and_none_do_not_crash():
    # I1: int / None list elements in iocs_enriched must not raise either.
    ti = _min_tool_input(mitre_techniques=[42], recommended_actions=[None], iocs_enriched=[None])
    out = extract_result(ti, _adversarial_ctx(), usage={"input_tokens": 1, "output_tokens": 2})
    assert isinstance(out["iris_description"], str)
    assert out["alert_iocs"] == []


def test_non_str_severity_does_not_crash_on_unhashable_lookup():
    # I1: a list-valued severity is unhashable -> _SEVERITY_IRIS_IDS.get would
    # TypeError. JS `{...}[r.severity]` yields undefined -> `|| 2` and never throws.
    ti = _min_tool_input(severity=["high"])
    out = extract_result(ti, _adversarial_ctx(), usage={"input_tokens": 1, "output_tokens": 2})
    assert out["severity_iris_id"] == 2                   # coalesced to default, no crash


def test_array_valued_iocs_survives_into_verify_body():
    # M1: JS keeps r.iocs when `typeof === 'object'` (true for a JS array); the
    # port must keep a list-valued iocs in verify_body.result.iocs rather than
    # replacing it with the five-bucket empty dict.
    ti = _min_tool_input(iocs=["evil.example"])
    out = extract_result(ti, _adversarial_ctx(), usage={"input_tokens": 1, "output_tokens": 2})
    assert out["verify_body"]["result"]["iocs"] == ["evil.example"]


def test_extract_result_no_tool_call_raises():
    with pytest.raises(NoToolCall):
        extract_result(None, _ctx_from(load_snapshot("splunk_baseline")))


def test_extract_result_does_not_mutate_caller_tool_input():
    snap = load_snapshot("splunk_baseline")
    tool_input = snap["opus_tool_input"]
    assert "investigation_notes" not in tool_input
    extract_result(tool_input, _ctx_from(snap), usage=snap["opus_usage"])
    assert "investigation_notes" not in tool_input


def test_extract_result_does_not_mutate_callers_nested_iocs_dict():
    # dict(tool_input) is a SHALLOW copy: r["iocs"] would still be the SAME dict
    # object as tool_input["iocs"] unless the port copies it too. A partial iocs
    # dict missing some buckets (e.g. only "ips") is exactly the PARTIAL-tool-call
    # shape the defensive fill exists for -- verify filling the missing buckets
    # doesn't leak into the caller's original iocs dict.
    tool_input = {
        "schema_version": "v1", "alert_summary": "s", "severity": "low",
        "severity_rationale": "r", "mitre_techniques": [], "iocs_enriched": [],
        "recommended_actions": [], "investigation_notes": "n",
        "iocs": {"ips": ["1.2.3.4"]},
    }
    ctx = {
        "source": "splunk", "run_id": "r1", "timestamp": "t1", "search_name": "s",
        "host": "h", "src_ip": "i", "console_link": "", "results_link": "",
        "retrieved_ids": [], "enrichment_results": {},
    }
    extract_result(tool_input, ctx, usage={"input_tokens": 1, "output_tokens": 2})
    assert tool_input["iocs"] == {"ips": ["1.2.3.4"]}


def test_extract_result_falcon_verify_body_matches_snapshot_and_contains_recommended():
    snap = load_snapshot("falcon_baseline")
    out = extract_result(snap["opus_tool_input"], _ctx_from(snap), usage=snap["opus_usage"])
    assert out["verify_body"] == snap["extract_result_output"]["verify_body"]
    assert out["contain_recommended"] is True
    desc = out["discord_body"]["embeds"][0]["description"]
    assert "⚠️ **Contain recommended** — run `falcon-contain` for vm-honeypot-win" in desc
    assert out["discord_body"] == snap["extract_result_output"]["discord_body"]
