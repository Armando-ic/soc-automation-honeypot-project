from red_team.harness.input_builder import parse_alert
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
