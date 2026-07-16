# grounding-service/tests/test_brake_evaluate.py
from grounding_service.brake import evaluate_egress

SPLUNK = "20.1.2.3"
# A small, convenient threshold for exercising the pure function's limbs. It is NOT the production
# default (150/400, decided 2026-07-16) -- that is pinned in test_brake_config.py. 25/200 still
# satisfies the deadness invariant 2*25 <= 200, so the egress_rate-is-dead proof below holds here.
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


def test_rate_trips_on_raw_unaggregated_events():
    # The arithmetic is right, but read the name literally: RAW, UNAGGREGATED. No feeder can
    # emit this shape -- see test_egress_rate_is_dead_against_both_real_feeders below. Kept as
    # unit coverage of the limb itself so it stays correct for a future weighted contract; it
    # is NOT evidence that the rate rule can fire in production, and was previously named as
    # though it were.
    events = [{"dst_ip": "93.184.1.1", "dst_port": 80} for _ in range(250)]
    out = evaluate_egress(events, **KW)
    assert out["trip"] is True and out["reason"] == "egress_rate"


def test_egress_rate_is_dead_against_both_real_feeders():
    # HONEST LIMITATION, pinned in executable form so it cannot quietly rot back into false
    # assurance. web_conns increments once per EVENT, but BOTH feeders pre-aggregate to one
    # row per distinct (dst_ip, dst_port): the host SPL via `stats count by DestinationIp,
    # DestinationPort` (its `count` column is dropped, not sent), the network KQL via
    # `distinct dst_ip, dst_port`. So conn_count <= 2 * distinct_dst, and the fan-out limb is
    # checked first. The rate rule is therefore dead so long as 2 * distinct_dst_max <=
    # conn_rate_max: at THIS test's 25/200 that is 50 <= 200, and at the production 150/400 it is
    # 300 <= 400 (pinned by test_rate_stays_dead_at_the_configured_thresholds). egress_fanout is
    # the only live THRESHOLD rule. Scoped deliberately: splunk_nonuf is live too and is checked
    # FIRST (it is why host_feed_spl carries the Splunk OR clause), and failsafe_malformed is live
    # but is a validation limb, not a signal.
    worst_case = [{"dst_ip": f"93.184.{i}.{i}", "dst_port": p}
                  for i in range(25) for p in (80, 443)]
    out = evaluate_egress(worst_case, **KW)
    assert out["distinct_dst"] == 25
    assert out["conn_count"] == 50          # the ceiling a real feeder can reach, vs a 200 gate
    assert out["trip"] is False

    # The consequence, stated as a test: the brake limits fan-out only. Concentrated traffic to a
    # single destination reaches it as ONE row, which neither limb sees, so the brake is not a
    # defense against concentrated third-party harm (that is the NSG's, Falcon's, and attended
    # monitoring's job). Catching it in the brake would need a per-event weight in the contract,
    # and the rate gate is un-baselined -- do not enable it blind.
    flood_as_the_feeder_reports_it = [{"dst_ip": "93.184.1.1", "dst_port": 443}]
    out = evaluate_egress(flood_as_the_feeder_reports_it, **KW)
    assert out["trip"] is False and out["conn_count"] == 1


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
