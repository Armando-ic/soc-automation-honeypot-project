from grounding_service.falcon import (
    advance_state,
    load_state,
    save_state,
    select_new_alert_ids,
)


def test_load_state_missing_returns_empty(tmp_path):
    assert load_state(tmp_path / "nope.json") == {"watermark": "", "seen": []}


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
