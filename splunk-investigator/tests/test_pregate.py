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
