from red_team.harness.input_builder import (
    build_opus_input,
    falcon_body_from_case,
    parse_alert,
    splunk_body_from_case,
)
from tests.conftest import load_snapshot


def test_parse_alert_matches_snapshot_fields():
    snap = load_snapshot("splunk_baseline")
    p = parse_alert(snap["webhook_body"])
    boi = snap["build_opus_input_output"]
    assert p["search_name"] == boi["search_name"]
    assert p["host"] == boi["host"]
    assert p["user"] == boi["user"]
    assert p["count"] == boi["count"]
    assert p["observed_iocs"] == boi["observed_iocs"]
    assert p["alert_text"] == boi["alert_text"]


def test_parse_alert_count_is_never_coerced():
    p = parse_alert({"result": {"count": "240 (see notes)"}})
    assert p["count"] == "240 (see notes)"


def test_parse_alert_private_ip_yields_no_observed_ip():
    p = parse_alert({"result": {"src_ip": "10.0.0.5"}})
    assert p["observed_iocs"]["ips"] == []


def _message_matches(snap_name: str):
    snap = load_snapshot(snap_name)
    boi = snap["build_opus_input_output"]
    p = parse_alert(snap["webhook_body"])
    out = build_opus_input(
        p,
        enrichment_results=boi["enrichment_results"],
        techniques=snap["retrieve_output"]["techniques"],   # production-sourced candidate menu
        retrieved_ids=snap["retrieve_output"]["ids"],
    )
    assert out["opus_user_message"] == boi["opus_user_message"]


def test_build_opus_message_byte_matches_splunk_snapshot():
    _message_matches("splunk_baseline")


def test_build_opus_message_byte_matches_falcon_snapshot():
    _message_matches("falcon_baseline")


def test_build_opus_input_merges_parsed_and_extra_keys():
    snap = load_snapshot("splunk_baseline")
    boi = snap["build_opus_input_output"]
    p = parse_alert(snap["webhook_body"])
    out = build_opus_input(
        p,
        enrichment_results=boi["enrichment_results"],
        techniques=snap["retrieve_output"]["techniques"],
        retrieved_ids=snap["retrieve_output"]["ids"],
    )
    # All parsed fields carry through untouched.
    for key, value in p.items():
        assert out[key] == value
    assert out["enrichment_results"] == boi["enrichment_results"]
    assert out["retrieved_ids"] == snap["retrieve_output"]["ids"]


def test_build_opus_input_no_candidates_or_enrichment_shows_none():
    p = parse_alert({"result": {}})
    out = build_opus_input(p, enrichment_results={}, techniques=[], retrieved_ids=[])
    assert "Candidate MITRE techniques (cite ONLY from these IDs):\n(none)" in out["opus_user_message"]
    assert "Enrichment results (verdicts you MUST match; do not invent):\n(none)" in out["opus_user_message"]


def test_build_opus_input_null_observed_ioc_buckets_coalesce_like_js():
    """M2: JS `(bucket || []).join(', ')` coalesces an explicit null bucket to []
    (renders "" / "(none)"), never a TypeError. A hand-built parsed dict with
    None ips/users/hosts and a technique with tactics=None must not crash."""
    parsed = {
        "search_name": "s", "host": "h", "user": "u", "count": "1",
        "results_link": "",
        "observed_iocs": {"ips": None, "domains": [], "file_hashes": [],
                          "users": None, "hosts": None},
    }
    techniques = [{"id": "T1110", "name": "Brute Force", "tactics": None}]
    out = build_opus_input(parsed, enrichment_results={}, techniques=techniques,
                           retrieved_ids=["T1110"])  # must not raise
    msg = out["opus_user_message"]
    assert "IPs: (none)" in msg          # null ips -> [] -> "" -> "(none)"
    assert "Users: \n" in msg            # null users -> [] -> "" (empty line)
    assert "[tactics: ]" in msg          # null tactics -> [] -> ""


def test_splunk_body_from_case_round_trips_through_parse_alert():
    alert = {
        "search_name": "Honeypot - Case Alert",
        "results_link": "http://splunk.example/search",
        "src_ip": "203.0.113.9",
        "user": "svc-account",
        "host": "vm-honeypot-win",
        "count": "7",
    }
    body = splunk_body_from_case(alert)
    assert body["source"] == "splunk"
    assert body["search_name"] == alert["search_name"]
    assert body["results_link"] == alert["results_link"]
    assert body["result"] == {
        "src_ip": "203.0.113.9",
        "user": "svc-account",
        "ComputerName": "vm-honeypot-win",
        "count": "7",
    }

    p = parse_alert(body)
    assert p["source"] == "splunk"
    assert p["search_name"] == alert["search_name"]
    assert p["host"] == "vm-honeypot-win"
    assert p["user"] == "svc-account"
    assert p["count"] == "7"
    assert p["observed_iocs"]["ips"] == ["203.0.113.9"]


def test_falcon_body_from_case_uses_map_alert_and_parses_cleanly():
    alert = {
        "severity_name": "High",
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "name": "Brute Force (High)",
        "user_name": "Administrator",
        "source_ips": ["198.51.100.7"],
        "host_names": ["vm-honeypot-win"],
        "origin_cid": "abc123",
        "id": "def456",
    }
    body = falcon_body_from_case(alert)
    assert body["source"] == "falcon"
    assert body["result"]["src_ip"] == "198.51.100.7"
    assert body["result"]["ComputerName"] == "vm-honeypot-win"

    p = parse_alert(body)
    assert p["source"] == "falcon"
    assert p["src_ip"] == "198.51.100.7"
    assert p["host"] == "vm-honeypot-win"
