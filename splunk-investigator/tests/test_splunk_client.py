# splunk-investigator/tests/test_splunk_client.py
import json
from pathlib import Path

import pytest

from splunk_investigator.splunk_client import parse_envelope

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "envelopes"


def _env(results, messages=None):
    return json.dumps({"preview": False, "messages": messages or [],
                       "fields": [], "results": results}).encode("utf-8")


def test_ok_rows():
    qr = parse_envelope(_env([{"success_count": "3", "fail_count": "40"}]), "logon_outcomes_for_ip", {}, 100)
    assert qr.outcome == "ok" and qr.row_count == 1


def test_clean_zero_rows_is_ok_not_error():
    qr = parse_envelope(_env([]), "logon_outcomes_for_ip", {}, 100)
    assert qr.outcome == "ok" and qr.row_count == 0


def test_fatal_message_maps_to_error_even_with_empty_results():
    qr = parse_envelope(_env([], messages=[{"type": "FATAL", "text": "Unknown field"}]),
                        "logon_outcomes_for_ip", {}, 100)
    assert qr.outcome == "error"


def test_over_cap_is_capped_incomplete():
    qr = parse_envelope(_env([{"x": "1"}] * 10), "user_targets_for_ip", {}, 5)
    assert qr.outcome == "capped_incomplete" and qr.row_count == 5


# --- extra precedence-edge locks (real behavior only, no filler) ---

def test_error_type_message_with_nonempty_results_is_still_error():
    # ERROR wins over "ok" even when results is non-empty -- error > capped > ok.
    qr = parse_envelope(
        _env([{"x": "1"}], messages=[{"type": "ERROR", "text": "field extraction failed"}]),
        "logon_outcomes_for_ip", {}, 100,
    )
    assert qr.outcome == "error" and qr.rows == () and qr.row_count == 0


def test_warn_truncated_message_maps_to_capped_incomplete_even_under_cap():
    # A WARN/truncation message caps the result even if len(results) <= result_cap.
    qr = parse_envelope(
        _env([{"x": "1"}, {"x": "2"}],
             messages=[{"type": "WARN", "text": "Results are truncated because the max results size has been exceeded"}]),
        "processes_by_user", {}, 100,
    )
    assert qr.outcome == "capped_incomplete"


def test_rows_values_stay_verbatim_strings_no_int_coercion():
    qr = parse_envelope(_env([{"success_count": "0", "fail_count": "40"}]), "logon_outcomes_for_ip", {}, 100)
    row = qr.rows[0]
    assert row["success_count"] == "0" and isinstance(row["success_count"], str)
    assert row["fail_count"] == "40" and isinstance(row["fail_count"], str)


# --- Fix 1: truncation keyword match must gate on type == "WARN" ---

def test_info_message_with_incomplete_keyword_under_cap_is_ok_not_capped():
    # A benign INFO message (e.g. a lookup-table refresh notice) containing
    # "incomplete" must NOT trip the truncation gate -- only a WARN-typed
    # message should. One legitimate row, under cap -> genuinely "ok".
    qr = parse_envelope(
        _env([{"x": "1"}],
             messages=[{"type": "INFO", "text": "Lookup table refresh incomplete, will retry next cycle"}]),
        "logon_outcomes_for_ip", {}, 100,
    )
    assert qr.outcome == "ok" and qr.row_count == 1


def test_warn_message_with_truncat_keyword_under_cap_is_still_capped_incomplete():
    # Confirms the WARN-typed truncation message still caps the result even
    # when len(results) <= result_cap (same case as
    # test_warn_truncated_message_maps_to_capped_incomplete_even_under_cap
    # above, re-asserted here to sit next to the new WARN-gating tests).
    qr = parse_envelope(
        _env([{"x": "1"}, {"x": "2"}],
             messages=[{"type": "WARN", "text": "Results are truncated because the max results size has been exceeded"}]),
        "processes_by_user", {}, 100,
    )
    assert qr.outcome == "capped_incomplete"


# --- Fix 2: row_count == len(rows) is locked, NOT forced to result_cap ---

def test_warn_truncated_under_cap_row_count_is_len_rows_not_result_cap():
    # 2 real rows, cap of 100 -- row_count must be 2 (len(rows)), never 100.
    # A future "fix" that forces row_count=result_cap must fail this test.
    qr = parse_envelope(
        _env([{"x": "1"}, {"x": "2"}],
             messages=[{"type": "WARN", "text": "Results are truncated because the max results size has been exceeded"}]),
        "processes_by_user", {}, 100,
    )
    assert qr.outcome == "capped_incomplete"
    assert qr.row_count == 2
    assert qr.row_count == len(qr.rows)


# --- Fix 3: cheap fixture round-trip -- catches catalog.py field-name drift ---

_FIXTURE_FILES = sorted(
    p for p in _FIXTURES_DIR.glob("*.json")
)


@pytest.mark.parametrize("fixture_path", _FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_envelopes_round_trip_ok_with_all_string_rows(fixture_path):
    raw = fixture_path.read_bytes()
    qr = parse_envelope(raw, fixture_path.stem, {}, result_cap=100)
    assert qr.outcome == "ok"
    for row in qr.rows:
        for value in row.values():
            assert isinstance(value, str)
