# splunk-investigator/tests/test_event_time.py
"""LB-1: normalize_event_time canonicalizes the alert's event_time so the
live saved-search shape (epoch earliest/latest, no ISO _time) still anchors
every time-bounded query. ISO passes through untouched; epoch seconds become
an ISO string catalog.render_spl can parse; anything else fails closed to ''
(preserving the '' -> render_error -> no-claim fail-safe, never a wall clock)."""
from datetime import datetime, timezone

from splunk_investigator.event_time import normalize_event_time


def test_naive_iso_passthrough_unchanged():
    assert normalize_event_time("2026-07-11T14:03:00") == "2026-07-11T14:03:00"


def test_aware_iso_passthrough_unchanged():
    assert normalize_event_time("2026-07-11T14:03:00+00:00") == "2026-07-11T14:03:00+00:00"


def test_z_suffixed_iso_passthrough_unchanged():
    # Falcon's created_timestamp is Z-suffixed; py3.11+ fromisoformat accepts it,
    # so it must pass through verbatim (not get re-derived through the epoch path).
    assert normalize_event_time("2026-07-11T14:03:00Z") == "2026-07-11T14:03:00Z"


def test_epoch_seconds_int_becomes_aware_utc_iso():
    # Epoch -> timezone-AWARE UTC ISO (with +00:00), so render_spl anchors it as
    # an ABSOLUTE instant (epoch Splunk bounds) rather than a tz-ambiguous
    # naive-local strftime. A naive-UTC output would be misread by a non-UTC
    # Splunk search head and shift the window off the real event.
    epoch = 1751500800
    expected = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
    assert normalize_event_time(epoch) == expected


def test_epoch_output_is_timezone_aware():
    # The aware-ness is load-bearing: catalog.render_spl branches on tzinfo to
    # decide absolute-epoch vs local-strftime bounds.
    out = normalize_event_time("1751500800")
    assert datetime.fromisoformat(out).tzinfo is not None


def test_epoch_seconds_numeric_string_becomes_aware_utc_iso():
    # Splunk's earliest(_time)/latest(_time) reach the webhook as epoch strings.
    epoch = 1751500800
    expected = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
    assert normalize_event_time("1751500800") == expected


def test_splunk_fractional_epoch_string_becomes_aware_utc_iso():
    # Splunk commonly renders epoch with a fractional part: "1751500800.000000".
    epoch = 1751500800.0
    expected = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
    assert normalize_event_time("1751500800.000000") == expected


def test_output_for_epoch_is_fromisoformat_parseable():
    # The whole point: the output must be something datetime.fromisoformat
    # (catalog.render_spl's parser) actually accepts, without raising.
    datetime.fromisoformat(normalize_event_time("1751500800"))


def test_empty_string_fails_closed_to_empty():
    assert normalize_event_time("") == ""


def test_none_fails_closed_to_empty():
    assert normalize_event_time(None) == ""


def test_garbage_text_fails_closed_to_empty():
    assert normalize_event_time("not-a-timestamp") == ""


def test_whitespace_only_fails_closed_to_empty():
    assert normalize_event_time("   ") == ""
