# splunk-investigator/tests/test_pregate.py
from splunk_investigator.pregate import should_investigate, _dedup_key
from splunk_investigator.config import load_config
import dataclasses

CFG = load_config()

def test_no_pivot_short_circuits():
    ok, reason = should_investigate({"src_ip": "", "host": ""}, CFG)
    assert ok is False and reason == "no_pivot"

def test_rfc1918_ip_only_is_no_pivot():
    ok, reason = should_investigate({"src_ip": "192.168.1.5", "host": ""}, CFG)
    assert ok is False and reason == "no_pivot"

def test_public_ip_investigated():
    ok, reason = should_investigate({"src_ip": "45.61.53.10", "host": "vm-honeypot-win"}, CFG)
    assert ok is True

def test_kill_switch():
    ok, reason = should_investigate({"src_ip": "45.61.53.10"}, dataclasses.replace(CFG, enabled=False))
    assert ok is False and reason == "kill_switch"

def test_budget_exhausted():
    ok, reason = should_investigate({"src_ip": "45.61.53.10"}, CFG, day_count=CFG.daily_budget)
    assert ok is False and reason == "budget_exhausted"

# --- coverage added beyond the brief's Step 1 tests: dedup is spend-controlling
# and was otherwise untested here. ---

def test_deduped_public_ip_short_circuits():
    alert = {"src_ip": "45.61.53.10", "host": "vm-honeypot-win", "event_time": "2026-07-11T14:03:00"}
    key = _dedup_key(alert, CFG)  # real key, not a hand-guessed string
    ok, reason = should_investigate(alert, CFG, seen={key})
    assert ok is False and reason == "deduped"

def test_host_only_alert_is_pivotable():
    ok, reason = should_investigate({"src_ip": "", "host": "vm-honeypot-win"}, CFG)
    assert ok is True and reason == ""

# --- review-fix round: multicast exclusion, dedup key hardening (typing/tz),
# public-ip-alone coverage, dedup-before-budget precedence ---

def test_multicast_ip_is_not_public():
    from splunk_investigator.pregate import _is_public_ip
    assert _is_public_ip("224.0.0.1") is False

def test_multicast_ip_only_is_no_pivot():
    ok, reason = should_investigate({"src_ip": "239.255.255.250", "host": ""}, CFG)
    assert ok is False and reason == "no_pivot"

def test_non_string_epoch_event_time_now_buckets_after_normalization():
    # LB-1 consistency: _dedup_key now normalizes event_time (epoch->ISO) the
    # same way agent.investigate does, so a numeric/epoch event_time produces a
    # REAL time bucket instead of degrading to the coarse src_ip-only
    # 'no-event-time' key (which would over-dedup a returning scanner once dedup
    # is wired). seen must be non-None so should_investigate calls _dedup_key.
    alert = {"src_ip": "45.61.53.10", "host": "vm-honeypot-win", "event_time": 1751500800}
    ok, reason = should_investigate(alert, CFG, seen=set())
    assert ok is True and reason == ""
    key = _dedup_key(alert, CFG)
    assert key != "45.61.53.10|no-event-time"
    assert key.startswith("45.61.53.10|")


def test_epoch_and_equivalent_iso_event_time_share_dedup_key():
    # The two event_time shapes the live pipeline can carry -- epoch seconds
    # (from `stats latest/earliest`) or an ISO string -- must land in the SAME
    # bucket so the two event_time CONSUMERS (pregate + agent) agree and a
    # returning scanner isn't split across buckets.
    from splunk_investigator.event_time import normalize_event_time
    epoch = 1751500800
    iso = normalize_event_time(epoch)
    a = {"src_ip": "45.61.53.10", "event_time": epoch}
    b = {"src_ip": "45.61.53.10", "event_time": iso}
    assert _dedup_key(a, CFG) == _dedup_key(b, CFG)

def test_tz_aware_event_times_same_instant_share_dedup_key():
    alert_utc = {"src_ip": "45.61.53.10", "host": "vm-honeypot-win", "event_time": "2026-07-11T14:03:00+00:00"}
    alert_offset = {"src_ip": "45.61.53.10", "host": "vm-honeypot-win", "event_time": "2026-07-11T10:03:00-04:00"}
    assert _dedup_key(alert_utc, CFG) == _dedup_key(alert_offset, CFG)

def test_public_ip_alone_is_pivotable():
    ok, reason = should_investigate({"src_ip": "45.61.53.10", "host": ""}, CFG)
    assert ok is True and reason == ""

def test_dedup_wins_over_budget_exhausted():
    alert = {"src_ip": "45.61.53.10", "host": "vm-honeypot-win", "event_time": "2026-07-11T14:03:00"}
    key = _dedup_key(alert, CFG)
    ok, reason = should_investigate(alert, CFG, seen={key}, day_count=CFG.daily_budget)
    assert ok is False and reason == "deduped"
