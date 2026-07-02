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


def test_scrub_replaces_first_occurrence_only():
    from red_team.harness.extract_result import _scrub_link  # helper the port factors out
    link = "http://vm-soc-v2-splunk/app?ref=vm-soc-v2-splunk"
    assert _scrub_link(link) == "http://x.x.x.x/app?ref=vm-soc-v2-splunk"


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
