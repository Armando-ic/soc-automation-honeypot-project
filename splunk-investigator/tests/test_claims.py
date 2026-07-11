# splunk-investigator/tests/test_claims.py
import pytest

from splunk_investigator.models import QueryResult, ScopeClaim
from splunk_investigator.claims import derive_claims


def _qr(name, outcome, rows, params=None):
    return QueryResult(query_name=name, params=params or {}, outcome=outcome,
                       rows=tuple(rows), row_count=len(rows))


def test_error_query_derives_no_claim():
    assert derive_claims(_qr("logon_outcomes_for_ip", "error", [])) == ()


def test_capped_query_derives_no_claim():
    assert derive_claims(_qr("logon_outcomes_for_ip", "capped_incomplete", [{"success_count": "1"}])) == ()


def test_ok_zero_rows_derives_explicit_negative_auth_claim():
    claims = derive_claims(_qr("logon_outcomes_for_ip", "ok", []))
    assert len(claims) == 1 and claims[0].type == "auth_outcome"
    assert claims[0].fields["success_count"] == 0 and claims[0].fields["fail_count"] == 0


def test_string_counts_are_coerced_to_int():
    claims = derive_claims(_qr("logon_outcomes_for_ip", "ok",
                               [{"ip": "45.61.53.10", "user": "Administrator",
                                 "success_count": "2", "fail_count": "58"}]))
    assert claims[0].fields["success_count"] == 2   # int, not "2"


def test_process_image_is_sanitized():
    claims = derive_claims(_qr("processes_by_user", "ok",
                               [{"host": "vm-honeypot-win", "user": "Administrator",
                                 "image": "evil\r\n| delete .exe", "count": "1"}]))
    assert "\r" not in claims[0].fields["image"] and "\n" not in claims[0].fields["image"]


# --- Step 5: required cases ---

def test_repeat_offender_sets_floored_when_first_seen_hits_lookback_floor():
    # Mirrors fixtures/envelopes/repeat_offender.json's row shape, but with
    # first_seen sitting on the info_min_time floor sentinel (the SPL's own
    # `floored=if(first_seen<=info_min_time+300,"true","false")` fired
    # "true" -- our job is just to parse that string to a real bool).
    claims = derive_claims(_qr("repeat_offender", "ok",
                               [{"first_seen": "1751500700.000000", "last_seen": "1752192180.000000",
                                 "info_min_time": "1751500700.000000", "days_active": "8.0",
                                 "floored": "true"}],
                               params={"ip": "45.61.53.10"}))
    assert len(claims) == 1 and claims[0].type == "repeat_offender"
    assert claims[0].fields["floored"] is True
    assert claims[0].fields["days_active"] == 8   # int, not "8.0"


def test_repeat_offender_not_floored_stays_false():
    claims = derive_claims(_qr("repeat_offender", "ok",
                               [{"first_seen": "1751500800.000000", "last_seen": "1752192180.000000",
                                 "info_min_time": "1751500700.000000", "days_active": "8.0",
                                 "floored": "false"}],
                               params={"ip": "45.61.53.10"}))
    assert claims[0].fields["floored"] is False


def test_distinct_targets_coerces_distinct_user_count_to_int():
    claims = derive_claims(_qr("user_targets_for_ip", "ok",
                               [{"distinct_user_count": "5"}],
                               params={"ip": "45.61.53.10"}))
    assert len(claims) == 1 and claims[0].type == "distinct_targets"
    assert claims[0].fields["distinct_user_count"] == 5
    assert isinstance(claims[0].fields["distinct_user_count"], int)


def test_nonnumeric_success_count_raises():
    with pytest.raises(ValueError):
        derive_claims(_qr("logon_outcomes_for_ip", "ok",
                          [{"success_count": "NaN", "fail_count": "1"}]))


# --- supplementary coverage: the other explicit-zero aggregate queries + ip/host sourcing ---

def test_distinct_targets_ok_zero_rows_is_explicit_zero_not_dropped():
    claims = derive_claims(_qr("user_targets_for_ip", "ok", [], params={"ip": "45.61.53.10"}))
    assert len(claims) == 1
    assert claims[0].fields["distinct_user_count"] == 0
    assert claims[0].fields["ip"] == "45.61.53.10"


def test_encoded_powershell_ok_zero_rows_is_explicit_zero_not_dropped():
    claims = derive_claims(_qr("encoded_powershell_on_host", "ok", [], params={"host": "vm-honeypot-win"}))
    assert len(claims) == 1 and claims[0].type == "encoded_powershell"
    assert claims[0].fields["count"] == 0
    assert claims[0].fields["host"] == "vm-honeypot-win"


def test_process_exec_multiple_rows_yield_multiple_claims():
    # processes_by_user's SPL is `stats count by host, User, Image` -- one
    # row per distinct image, so one claim per row (not a single aggregate).
    claims = derive_claims(_qr("processes_by_user", "ok", [
        {"host": "vm-honeypot-win", "user": "Administrator", "image": "C:\\Windows\\System32\\cmd.exe", "count": "6"},
        {"host": "vm-honeypot-win", "user": "Administrator", "image": "C:\\Windows\\System32\\whoami.exe", "count": "1"},
    ]))
    assert len(claims) == 2
    assert {c.fields["image"] for c in claims} == {"C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\whoami.exe"}
    assert claims[0].fields["count"] == 6 and claims[1].fields["count"] == 1


def test_process_exec_ok_zero_rows_derives_no_claim():
    # No distinct-image identity to hang a claim on -- unlike the scalar
    # aggregate queries, an empty processes_by_user result derives nothing
    # (queries_run still records outcome=ok/row_count=0 upstream).
    assert derive_claims(_qr("processes_by_user", "ok", [])) == ()


def test_ip_and_host_fall_back_to_query_params_when_absent_from_row():
    # logon_outcomes_for_ip's SPL never emits an "ip" field on the row (it
    # aggregates across the whole search, not "by" ip) -- the entity comes
    # from the params the query was actually run with.
    claims = derive_claims(_qr("logon_outcomes_for_ip", "ok",
                               [{"success_count": "2", "fail_count": "58"}],
                               params={"ip": "45.61.53.10", "window": "-24h"}))
    assert claims[0].fields["ip"] == "45.61.53.10"


def test_repeat_offender_ok_zero_rows_derives_no_claim():
    # No first_seen/last_seen to report -- a temporal claim can't be
    # meaningfully zeroed the way a scalar count can.
    assert derive_claims(_qr("repeat_offender", "ok", [], params={"ip": "45.61.53.10"})) == ()
