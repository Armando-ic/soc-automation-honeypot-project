from datetime import datetime, timezone

from grounding_service.falcon import (
    advance_state,
    default_watermark,
    load_state,
    save_state,
    select_new_alert_ids,
)


def test_default_watermark_is_now_minus_24h_iso_z():
    now = datetime(2026, 6, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert default_watermark(now) == "2026-06-28T12:00:00Z"


def test_load_state_missing_returns_bounded_default(tmp_path):
    now = datetime(2026, 6, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert load_state(tmp_path / "nope.json", now=now) == {
        "watermark": "2026-06-28T12:00:00Z", "seen": []}


def test_load_state_empty_watermark_bounded_seen_preserved(tmp_path):
    p = tmp_path / "state.json"
    save_state(p, {"watermark": "", "seen": ["x"]})
    now = datetime(2026, 6, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert load_state(p, now=now) == {
        "watermark": "2026-06-28T12:00:00Z", "seen": ["x"]}


def test_load_state_preserves_real_watermark(tmp_path):
    p = tmp_path / "state.json"
    save_state(p, {"watermark": "2026-06-29T15:11:34.51Z", "seen": ["a"]})
    now = datetime(2026, 6, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert load_state(p, now=now) == {
        "watermark": "2026-06-29T15:11:34.51Z", "seen": ["a"]}


def test_save_then_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    save_state(p, {"watermark": "2026-06-29T00:00:00Z", "seen": ["a", "b"]})
    assert load_state(p) == {"watermark": "2026-06-29T00:00:00Z", "seen": ["a", "b"]}


def test_select_drops_seen_and_caps_oldest_first():
    # candidate_ids arrive oldest-first (query sorts asc)
    out = select_new_alert_ids(["a", "b", "c", "d"], seen=["b"], cap=2)
    assert out == ["a", "c"]


def test_select_empty_when_all_seen():
    assert select_new_alert_ids(["a", "b"], seen=["a", "b"], cap=5) == []


def test_advance_contiguous_prefix_only():
    # b fails -> watermark stops at a's created; c (later) is NOT acked even if ok,
    # so c is re-pulled next tick (>= watermark, not in seen) -> no SKIP.
    state = {"watermark": "", "seen": []}
    results = [
        {"composite_id": "a", "created": "2026-06-29T01:00:00Z", "ok": True},
        {"composite_id": "b", "created": "2026-06-29T02:00:00Z", "ok": False},
        {"composite_id": "c", "created": "2026-06-29T03:00:00Z", "ok": True},
    ]
    new = advance_state(state, results)
    assert new["watermark"] == "2026-06-29T01:00:00Z"
    assert new["seen"] == ["a"]


def test_advance_all_ok_takes_max_created():
    state = {"watermark": "2026-06-28T00:00:00Z", "seen": ["x"]}
    results = [
        {"composite_id": "a", "created": "2026-06-29T01:00:00Z", "ok": True},
        {"composite_id": "b", "created": "2026-06-29T02:00:00Z", "ok": True},
    ]
    new = advance_state(state, results)
    assert new["watermark"] == "2026-06-29T02:00:00Z"
    assert new["seen"] == ["x", "a", "b"]


def test_advance_bounds_seen():
    state = {"watermark": "", "seen": [str(i) for i in range(5000)]}
    results = [{"composite_id": "new", "created": "2026-06-29T01:00:00Z", "ok": True}]
    new = advance_state(state, results, seen_max=5000)
    assert len(new["seen"]) == 5000
    assert new["seen"][-1] == "new"
    assert "0" not in new["seen"]


from grounding_service.falcon import alert_created, composite_id_of, map_alert, map_alerts

BEHAVIORAL = {  # real us-2 EICAR behavioral alert shape (Task 0 live dump 2026-06-29)
    "origin_cid": "00000000000000000000000000000000",
    "id": "ind:11111111111111111111111111111111:5106908871-10418-995344",
    "timestamp": "2026-06-29T15:10:32.158Z",
    "updated_timestamp": "2026-06-29T16:10:47.694989879Z",
    "severity_name": "Informational", "tactic": "Execution", "technique": "User Execution",
    "technique_id": "T1204", "name": "EICARTestFileWrittenWin", "user_name": "analyst",
    "md5": "dd6f4b7818a253887b8ea86515f6fb7d",
    "sha256": "38f4384643b3fa0de714d2367b712c2e0fa1c89e2cfd131ae6b831ad962b1033",
    "sha1": "0000000000000000000000000000000000000000",
    "source_ips": [],
}

NETWORK = {  # synthetic IP-bearing alert: source_ips array + created_timestamp present
    "composite_id": "cid:ind:aid:1-2-3", "created_timestamp": "2026-06-29T16:00:00Z",
    "severity_name": "High", "tactic": "Credential Access", "technique": "Brute Force",
    "technique_id": "T1110", "source_ips": ["203.0.113.10"], "user_name": "Administrator",
}


def test_composite_id_reconstructed_from_origin_cid_and_id():
    assert composite_id_of(BEHAVIORAL) == (
        "00000000000000000000000000000000:ind:11111111111111111111111111111111:5106908871-10418-995344")
    assert composite_id_of(NETWORK) == "cid:ind:aid:1-2-3"        # used directly when present


def test_alert_created_prefers_created_timestamp_then_timestamp():
    assert alert_created(NETWORK) == "2026-06-29T16:00:00Z"        # created_timestamp
    assert alert_created(BEHAVIORAL) == "2026-06-29T15:10:32.158Z" # falls back to timestamp


def test_map_behavioral_empty_ip_no_undefined():
    body = map_alert(BEHAVIORAL)
    assert body["source"] == "falcon"
    assert body["result"]["src_ip"] == ""                  # source_ips empty -> empty-IOC path
    assert body["result"]["ComputerName"] == "vm-honeypot-win"
    assert body["result"]["count"] == 1
    for bad in ("undefined", "None"):
        assert bad not in body["alert_text"]
    assert "T1204" in body["alert_text"]
    assert "EICARTestFileWrittenWin" in body["alert_text"]
    assert "38f4384643" in body["alert_text"]              # real sha256 surfaced
    assert body["console_link"].endswith("5106908871-10418-995344")


def test_map_skips_zero_placeholder_hash():
    assert "0000000000000000000000000000000000000000" not in map_alert(BEHAVIORAL)["alert_text"]


def test_map_network_alert_sets_ip_from_source_ips():
    body = map_alert(NETWORK)
    assert body["result"]["src_ip"] == "203.0.113.10"
    assert body["result"]["user"] == "Administrator"
    assert "T1110" in body["alert_text"]


def test_map_ignores_private_or_garbage_ip():
    assert map_alert(dict(NETWORK, source_ips=["10.0.0.5"]))["result"]["src_ip"] == ""
    assert map_alert(dict(NETWORK, source_ips=["not-an-ip"]))["result"]["src_ip"] == ""


def test_map_alerts_sorts_oldest_first_regardless_of_hydrate_order():
    # CrowdStrike entities/alerts/v2 does NOT guarantee request order; map_alerts must re-sort by
    # `created` so advance_state's contiguous-prefix watermark can't strand an earlier alert (SKIP).
    a = dict(NETWORK, composite_id="a:1", created_timestamp="2026-06-29T03:00:00Z")
    b = dict(NETWORK, composite_id="b:2", created_timestamp="2026-06-29T01:00:00Z")
    c = dict(NETWORK, composite_id="c:3", created_timestamp="2026-06-29T02:00:00Z")
    items = map_alerts([a, b, c])                        # scrambled input: 03:00, 01:00, 02:00
    assert [it["created"] for it in items] == [
        "2026-06-29T01:00:00Z", "2026-06-29T02:00:00Z", "2026-06-29T03:00:00Z"]
    assert [it["composite_id"] for it in items] == ["b:2", "c:3", "a:1"]
    assert items[0]["body"]["source"] == "falcon"       # full webhook body still built per alert


def test_map_alerts_empty_created_sorts_first():
    # a timestamp-less alert must never advance the watermark -> acked earliest (sorts first)
    no_ts = {"composite_id": "x:0"}                      # no created_timestamp/timestamp -> created ""
    a = dict(NETWORK, composite_id="a:1", created_timestamp="2026-06-29T01:00:00Z")
    items = map_alerts([a, no_ts])
    assert items[0]["composite_id"] == "x:0"
    assert items[0]["created"] == ""


def test_map_alert_reads_real_host_from_host_names():
    # host-scope was dropped from the FQL, so a stray host's alert can enter; map must NOT relabel
    # it as the honeypot — read the alert's real host (host_names[0]) for ComputerName + alert_text.
    body = map_alert(dict(NETWORK, host_names=["other-host"]))
    assert body["result"]["ComputerName"] == "other-host"
    assert "other-host" in body["alert_text"]


def test_map_alert_reads_logon_domain_when_no_host_names():
    # distinct from HOST_DEFAULT so this proves logon_domain is actually read (not a coincidental pass)
    body = map_alert(dict(NETWORK, logon_domain="vm-other-host"))
    assert body["result"]["ComputerName"] == "vm-other-host"


def test_map_alert_defaults_host_when_absent():
    # no host_names/logon_domain -> default HOST_DEFAULT (BEHAVIORAL/NETWORK fixtures carry neither)
    assert map_alert(NETWORK)["result"]["ComputerName"] == "vm-honeypot-win"
    assert map_alert(BEHAVIORAL)["result"]["ComputerName"] == "vm-honeypot-win"


import pytest

from grounding_service.falcon import select_contain_aid

PIN = "9134deadbeef5865"


def test_contain_guard_happy():
    assert select_contain_aid([PIN], PIN) == PIN


def test_contain_guard_rejects_zero_matches():
    with pytest.raises(ValueError):
        select_contain_aid([], PIN)


def test_contain_guard_rejects_multiple_matches():
    with pytest.raises(ValueError):
        select_contain_aid([PIN, "other"], PIN)


def test_contain_guard_rejects_wrong_aid():
    with pytest.raises(ValueError):
        select_contain_aid(["someoneelse"], PIN)


def test_contain_guard_rejects_unconfigured_pin():
    with pytest.raises(ValueError):
        select_contain_aid([PIN], "")
