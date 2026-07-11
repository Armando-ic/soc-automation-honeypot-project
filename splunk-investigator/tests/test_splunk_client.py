# splunk-investigator/tests/test_splunk_client.py
import json

from splunk_investigator.splunk_client import parse_envelope


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
