# grounding-service/tests/test_brake_evaluate.py
from grounding_service.brake import evaluate_egress

SPLUNK = "20.1.2.3"
KW = dict(splunk_host_ip=SPLUNK, distinct_dst_max=25, conn_rate_max=200)


def test_quiet_normal_intrusion_does_not_trip():
    # a handful of web connections to a few hosts - normal post-exploitation
    events = [{"dst_ip": f"93.184.0.{i}", "dst_port": 443} for i in range(5)]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is False and out["reason"] == ""


def test_fanout_trips():
    events = [{"dst_ip": f"93.184.{i}.{i}", "dst_port": 443} for i in range(40)]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is True and out["reason"] == "egress_fanout"
    assert out["distinct_dst"] == 40


def test_rate_trips_even_with_few_destinations():
    events = [{"dst_ip": "93.184.1.1", "dst_port": 80} for _ in range(250)]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is True and out["reason"] == "egress_rate"


def test_splunk_nonuf_port_trips():
    events = [{"dst_ip": SPLUNK, "dst_port": 8089}]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is True and out["reason"] == "splunk_nonuf"


def test_splunk_uf_port_is_allowed():
    events = [{"dst_ip": SPLUNK, "dst_port": 9997} for _ in range(10)]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is False


def test_splunk_traffic_excluded_from_fanout_count():
    # UF traffic to Splunk must not inflate the web fan-out distinct count
    events = [{"dst_ip": SPLUNK, "dst_port": 9997} for _ in range(50)]
    out = evaluate_egress(events, **KW)
    assert out["distinct_dst"] == 0 and out["trip"] is False


def test_malformed_toplevel_fails_closed():
    assert evaluate_egress(None, **KW)["trip"] is True
    assert evaluate_egress("not-a-list", **KW)["reason"] == "failsafe_malformed"


def test_unparseable_element_is_skipped_not_fatal():
    events = [{"dst_ip": "93.184.1.1", "dst_port": "not-int"},
              {"dst_ip": "93.184.1.2", "dst_port": 443}]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is False        # one good web conn, one skipped - quiet
