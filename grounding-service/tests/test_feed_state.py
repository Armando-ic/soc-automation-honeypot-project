"""Feeder liveness watermark (session 40).

The brake structurally CANNOT tell a quiet box from a dead feeder: evaluate_egress([]) and
evaluate_egress([{'dst_ip':'10.0.0.4','dst_port':3389}]) both return
{'trip': False, 'distinct_dst': 0, 'conn_count': 0}. Measured live 2026-07-15, 24h of real
telemetry produced ZERO rows on the watched ports, so on this honeypot the HEALTHY steady state
is byte-identical to total feeder failure. This watermark is what makes them distinguishable:
a live feeder POSTS every minute even when it has nothing to report, so it is the ARRIVAL of
calls, not their contents, that proves liveness.

It lives SOC-side on purpose. A trip severs the honeypot's own 9997 forwarding (the deny rule
is priority 100 with protocol/port "*", allow-splunk-telemetry is 1000, lowest wins), so every
honeypot-side signal dies exactly when it matters.
"""
from datetime import datetime, timezone

from grounding_service.feed_state import load_feed_state, record_post, save_feed_state, summarize

T0 = datetime(2026, 7, 15, 22, 0, 0, tzinfo=timezone.utc)


def _at(seconds):
    return datetime.fromtimestamp(T0.timestamp() + seconds, tz=timezone.utc)


def test_load_missing_file_is_well_typed_empty(tmp_path):
    # Never raise on a fresh deploy: no file yet is the normal first-boot state.
    st = load_feed_state(tmp_path / "nope.json")
    assert st == {"last_post_at": "", "total_posts": 0, "recent": []}


def test_load_corrupt_file_degrades_to_empty(tmp_path):
    # A half-written or hand-edited file must not take the endpoint down. Liveness telemetry is
    # never worth breaking the brake for.
    p = tmp_path / "feed.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_feed_state(p) == {"last_post_at": "", "total_posts": 0, "recent": []}


def test_record_post_stamps_the_injected_clock_not_wall_clock(tmp_path):
    # Injected clock, deliberately. The two known-red falcon watermark tests are red precisely
    # because load_state falls back to datetime.now() at the endpoint boundary, so their
    # assertions rot against real time. This takes `now` as an argument, always.
    st = record_post(load_feed_state(tmp_path / "f.json"),
                     now=T0, distinct_dst=3, conn_count=3, source="splunk", trip=False)
    assert st["last_post_at"] == "2026-07-15T22:00:00Z"
    assert st["total_posts"] == 1
    assert st["recent"] == [{"at": "2026-07-15T22:00:00Z", "distinct_dst": 3,
                             "conn_count": 3, "source": "splunk", "trip": False}]


def test_a_quiet_box_still_records_a_post(tmp_path):
    # THE distinction the brake cannot make. A quiet box POSTS events:[] -> distinct_dst 0. That
    # is a live feeder with nothing to say, and it must be recorded exactly like any other call:
    # liveness is proven by ARRIVAL, not by content.
    st = record_post(load_feed_state(tmp_path / "f.json"),
                     now=T0, distinct_dst=0, conn_count=0, source="splunk", trip=False)
    assert st["total_posts"] == 1
    assert st["last_post_at"] == "2026-07-15T22:00:00Z"


def test_recent_is_capped_and_keeps_the_newest(tmp_path):
    # 1440 posts/day forever: the ring must not grow without bound, and truncation must drop the
    # OLDEST, since the whole point is the recent distribution.
    st = load_feed_state(tmp_path / "f.json")
    for i in range(10):
        st = record_post(st, now=_at(i), distinct_dst=i, conn_count=i, source="splunk",
                         trip=False, keep=4)
    assert st["total_posts"] == 10           # the counter still counts every post
    assert len(st["recent"]) == 4
    assert [r["distinct_dst"] for r in st["recent"]] == [6, 7, 8, 9]


def test_summarize_reports_age_and_staleness_from_the_injected_clock(tmp_path):
    st = record_post(load_feed_state(tmp_path / "f.json"),
                     now=T0, distinct_dst=3, conn_count=3, source="splunk", trip=False)
    fresh = summarize(st, now=_at(60), stale_after_s=300)
    assert fresh["age_seconds"] == 60
    assert fresh["stale"] is False
    # The feeder posts every 60s. Five missed ticks is not a blip, it is a dead feeder.
    dead = summarize(st, now=_at(301), stale_after_s=300)
    assert dead["age_seconds"] == 301
    assert dead["stale"] is True


def test_summarize_with_no_posts_ever_is_stale_not_healthy(tmp_path):
    # FAIL-SAFE DIRECTION. A feeder that has never posted is the most broken state there is; it
    # must never read as healthy just because there is no evidence against it.
    s = summarize(load_feed_state(tmp_path / "f.json"), now=T0, stale_after_s=300)
    assert s["stale"] is True
    assert s["age_seconds"] is None
    assert s["last_post_at"] == ""
    assert s["total_posts"] == 0


def test_summarize_exposes_the_distinct_dst_distribution(tmp_path):
    # The threshold baseline. BRAKE_DISTINCT_DST_MAX=25 was never measured with an attacker on
    # the box, and the closed-box baseline is 0 -- the regime where the feeder does not matter.
    # This is what answers it with data once the box is open: a Tor bootstrap (~30 distinct on
    # 443, tor.exe is in the Sysmon include by name) would show up here BEFORE anyone has to
    # guess whether 25 is right.
    st = load_feed_state(tmp_path / "f.json")
    for i, d in enumerate([0, 0, 3, 30, 1]):
        st = record_post(st, now=_at(i), distinct_dst=d, conn_count=d, source="splunk",
                         trip=(d > 25))
    s = summarize(st, now=_at(10), stale_after_s=300)
    assert s["max_distinct_dst"] == 30
    assert s["samples"] == 5
    assert s["trips"] == 1


def test_state_round_trips_through_disk(tmp_path):
    p = tmp_path / "feed.json"
    st = record_post(load_feed_state(p), now=T0, distinct_dst=7, conn_count=9,
                     source="nsg", trip=False)
    save_feed_state(p, st)
    assert load_feed_state(p) == st
