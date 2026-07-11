"""Task 10: deterministic scope_grounded check family.

scope_evidence is supplied OUT OF MODEL CONTROL (the harness's live Splunk
claims), never the model's own scope_findings. These tests pin:
  - scope_findings_grounded: model's scope_findings must field-for-field
    equal a claim in scope_evidence, fail CLOSED when evidence is absent.
  - scope_notes_honesty: investigation_notes can't assert a scope outcome
    (successful logon/auth, lateral movement, exfil, post-exploit) that
    isn't backed by a grounded finding.
  - severity_supported: high/critical can now also be backed by grounded
    scope_evidence (not the model's own scope_findings), on top of the
    original bad-ioc / hot-tactic paths.
"""
from tests.conftest import status_of


def _status(report, name):
    """Like status_of, but returns the plain string value ("passed"/"failed"/...)
    so tests can compare against plain strings per the Task 10 brief."""
    status = status_of(report, name)
    return status.value if status is not None else None

SCOPE_EV = {"claims": [{"type": "auth_outcome", "ip": "45.61.53.10", "user": "Administrator",
                        "success_count": 1, "fail_count": 40}], "queries_run": []}

_BASE = {
    "schema_version": "v1",
    "alert_summary": "test alert",
    "severity": "low",
    "severity_rationale": "test",
    "mitre_techniques": [],
    "iocs": {"ips": [], "domains": [], "file_hashes": [], "users": [], "hosts": []},
    "iocs_enriched": [],
    "recommended_actions": [],
    "investigation_notes": "",
}


def _result(**over):
    base = dict(_BASE)
    base["src_ip"] = "45.61.53.10"
    base["scope_findings"] = []
    base.update(over)
    return base


# --- scope_findings_grounded --------------------------------------------------

def test_scope_findings_must_match_field_for_field(verifier):
    r = _result(scope_findings=[{"type": "auth_outcome", "ip": "45.61.53.10",
                                 "user": "Administrator", "success_count": 50, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=SCOPE_EV)
    assert _status(rep, "scope_findings_grounded") == "failed"   # 50 != 1


def test_non_empty_scope_findings_with_absent_evidence_fails_closed(verifier):
    r = _result(scope_findings=[{"type": "auth_outcome", "ip": "45.61.53.10",
                                 "user": "Administrator", "success_count": 1, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=None)
    assert _status(rep, "scope_findings_grounded") == "failed"   # fail closed, not NOT_APPLICABLE


def test_empty_scope_findings_passes_even_without_evidence(verifier):
    r = _result(scope_findings=[])
    rep = verifier.verify(r, scope_evidence=None)
    assert _status(rep, "scope_findings_grounded") == "passed"


def test_missing_scope_findings_key_passes(verifier):
    base = dict(_BASE)
    base["src_ip"] = "45.61.53.10"
    # no scope_findings key at all
    rep = verifier.verify(base, scope_evidence=None)
    assert _status(rep, "scope_findings_grounded") == "passed"


def test_scope_finding_grounded_when_exact_match(verifier):
    r = _result(scope_findings=[{"type": "auth_outcome", "ip": "45.61.53.10",
                                 "user": "Administrator", "success_count": 1, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=SCOPE_EV)
    assert _status(rep, "scope_findings_grounded") == "passed"


def test_scope_finding_canonicalizes_ip_before_comparing(verifier):
    # Same address, differently-formatted (expanded vs compressed IPv6) --
    # canonicalization must treat these as equal.
    ev = {"claims": [{"type": "auth_outcome",
                      "ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
                      "user": "Administrator", "success_count": 1, "fail_count": 40}],
          "queries_run": []}
    r = _result(scope_findings=[{"type": "auth_outcome", "ip": "2001:db8::1",
                                 "user": "Administrator", "success_count": 1, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "scope_findings_grounded") == "passed"


def test_scope_finding_with_none_user_matches_grounded_claim_with_none_user(verifier):
    # auth_outcome.user is ALWAYS None in v1 (no user param on the logon query) --
    # None must equal None, not be treated as a mismatch.
    ev = {"claims": [{"type": "auth_outcome", "ip": "45.61.53.10", "user": None,
                      "success_count": 1, "fail_count": 40}], "queries_run": []}
    r = _result(scope_findings=[{"type": "auth_outcome", "ip": "45.61.53.10", "user": None,
                                 "success_count": 1, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "scope_findings_grounded") == "passed"


# --- severity_supported (scope-only backing) ---------------------------------

def test_scope_only_high_needs_attacker_ip_success(verifier):
    r = _result(severity="high")                                  # no bad ioc, no hot tactic
    rep = verifier.verify(r, scope_evidence=SCOPE_EV)             # has success_count=1 for src_ip
    assert _status(rep, "severity_supported") == "passed"


def test_scope_only_high_rejected_without_success(verifier):
    ev = {"claims": [{"type": "auth_outcome", "ip": "45.61.53.10", "user": "Administrator",
                      "success_count": 0, "fail_count": 40}], "queries_run": []}
    r = _result(severity="high")
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "severity_supported") == "failed"


def test_high_still_fails_when_scope_evidence_is_none(verifier):
    r = _result(severity="high")
    rep = verifier.verify(r, scope_evidence=None)
    assert _status(rep, "severity_supported") == "failed"


def test_scope_only_high_rejected_when_auth_outcome_is_about_a_different_ip(verifier):
    ev = {"claims": [{"type": "auth_outcome", "ip": "8.8.8.8", "user": "Administrator",
                      "success_count": 1, "fail_count": 40}], "queries_run": []}
    r = _result(severity="high")
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "severity_supported") == "failed"


def test_scope_only_critical_needs_auth_success_plus_process_activity_on_host(verifier):
    ev = {"claims": [
        {"type": "auth_outcome", "ip": "45.61.53.10", "user": "Administrator",
         "success_count": 1, "fail_count": 40},
        {"type": "encoded_powershell", "host": "vm-honeypot-win", "count": 2},
    ], "queries_run": []}
    r = _result(severity="critical", host="vm-honeypot-win")
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "severity_supported") == "passed"


def test_scope_only_critical_rejected_when_process_claim_count_is_zero(verifier):
    # claims.py emits encoded_powershell with count=0 on an empty-ok result --
    # that ZERO must NOT back CRITICAL.
    ev = {"claims": [
        {"type": "auth_outcome", "ip": "45.61.53.10", "user": "Administrator",
         "success_count": 1, "fail_count": 40},
        {"type": "encoded_powershell", "host": "vm-honeypot-win", "count": 0},
    ], "queries_run": []}
    r = _result(severity="critical", host="vm-honeypot-win")
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "severity_supported") == "failed"


def test_scope_only_critical_rejected_with_only_bare_process_claim_no_auth(verifier):
    ev = {"claims": [{"type": "encoded_powershell", "host": "vm-honeypot-win", "count": 3}],
          "queries_run": []}
    r = _result(severity="critical", host="vm-honeypot-win")
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "severity_supported") == "failed"


# --- scope_notes_honesty ------------------------------------------------------

def test_notes_honesty_flags_ungrounded_successful_logon_claim(verifier):
    r = _result(investigation_notes="Confirmed successful logon from the attacker.")
    rep = verifier.verify(r, scope_evidence=None)
    assert _status(rep, "scope_notes_honesty") == "failed"


def test_notes_honesty_passes_when_backed_by_grounded_finding(verifier):
    r = _result(investigation_notes="Confirmed successful logon from the attacker.",
                scope_findings=[{"type": "auth_outcome", "ip": "45.61.53.10",
                                 "user": "Administrator", "success_count": 1, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=SCOPE_EV)
    assert _status(rep, "scope_notes_honesty") == "passed"


def test_notes_honesty_ignores_negated_assertion(verifier):
    r = _result(investigation_notes="Brute force only; no successful logon observed yet.")
    rep = verifier.verify(r, scope_evidence=None)
    assert _status(rep, "scope_notes_honesty") == "passed"


def test_notes_honesty_flags_ungrounded_lateral_movement_claim(verifier):
    r = _result(investigation_notes="Evidence of lateral movement to a second host.")
    rep = verifier.verify(r, scope_evidence=SCOPE_EV)
    assert _status(rep, "scope_notes_honesty") == "failed"


def test_notes_honesty_passes_on_scope_silent_notes(verifier):
    r = _result(investigation_notes="Standard brute-force pattern, nothing unusual.")
    rep = verifier.verify(r, scope_evidence=None)
    assert _status(rep, "scope_notes_honesty") == "passed"
