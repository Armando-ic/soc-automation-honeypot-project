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


def test_non_dict_scope_finding_fails_closed_without_raising(verifier):
    # scope_findings is model-controlled and NOT schema-validated -- a non-dict
    # entry (adversarial or malformed model output) must fail closed, not crash.
    r = _result(scope_findings=["not-a-dict"])
    rep = verifier.verify(r, scope_evidence=SCOPE_EV)
    assert _status(rep, "scope_findings_grounded") == "failed"


def test_non_dict_claim_in_scope_evidence_fails_closed_without_raising(verifier):
    # scope_evidence["claims"] is out-of-model-control ground truth, but guard
    # both sides defensively: a non-dict claim must not crash the comparison.
    ev = {"claims": ["not-a-dict-claim"], "queries_run": []}
    r = _result(scope_findings=[{"type": "auth_outcome", "ip": "45.61.53.10",
                                 "user": "Administrator", "success_count": 1, "fail_count": 40}])
    rep = verifier.verify(r, scope_evidence=ev)
    assert _status(rep, "scope_findings_grounded") == "failed"


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


# --- LB-2: the PRODUCTION verify_body.result shape --------------------------
# Extract Result now threads the ground-truth entities into the result OUT OF
# MODEL CONTROL: result = { ...r, src_ip: ctx.src_ip, host: ctx.pivot_host }.
# The 65-suite above uses _result(), which injects src_ip -- a shape the wire
# never produced before the LB-2 fix. These lock the real end-to-end contract on
# the exact shape the builder now emits, so the masking can't recur.

_MODEL_OUTPUT = {   # what submit_triage_result returns: NO src_ip/host of its own
    "schema_version": "v1",
    "alert_summary": "brute force with a successful logon and encoded PowerShell",
    "severity": "critical",
    "severity_rationale": "confirmed compromise",
    "mitre_techniques": [],
    "iocs": {"ips": [], "domains": [], "file_hashes": [], "users": [], "hosts": []},
    "iocs_enriched": [],
    "recommended_actions": [],
    "investigation_notes": "",
    "scope_findings": [],
}

_CRIT_EV = {"claims": [
    {"type": "auth_outcome", "ip": "45.61.53.10", "user": "Administrator",
     "success_count": 1, "fail_count": 40},
    {"type": "encoded_powershell", "host": "vm-honeypot-win", "count": 2},
], "queries_run": []}


def test_lb2_production_wire_shape_backs_grounded_critical(verifier):
    # result = { ...model_output, src_ip: ctx.src_ip, host: ctx.host } -- the
    # post-fix shape. Grounded CRITICAL fires (auth success + process on host).
    result = {**_MODEL_OUTPUT, "src_ip": "45.61.53.10", "host": "vm-honeypot-win"}
    rep = verifier.verify(result, scope_evidence=_CRIT_EV)
    assert _status(rep, "severity_supported") == "passed"


def test_lb2_without_threaded_entity_grounded_severity_is_inert(verifier):
    # The PRE-fix shape: model output alone, no src_ip/host on the result. Even
    # with fully-backing scope_evidence, grounded severity must NOT fire because
    # norm.get('src_ip') is None -- this is the exact LB-2 bug signature, locked
    # so a regression that drops the JS_EXTRACT threading is caught end-to-end.
    result = dict(_MODEL_OUTPUT)   # no src_ip/host threaded in
    rep = verifier.verify(result, scope_evidence=_CRIT_EV)
    assert _status(rep, "severity_supported") == "failed"


def test_lb2_nohost_live_shape_grounded_critical_fails_closed_honestly(verifier):
    # The LIVE honeypot saved search ends in `| stats ... by src_ip`, dropping
    # ComputerName -> pivot_host='' -> verify_body.result.host=''. Even if the
    # engine DISCOVERED a host from the 4625 rows and emitted a process claim on
    # it, grounded CRITICAL must fail CLOSED here (norm.host='' -> the critical
    # branch returns False before matching) rather than pass on the sentinel.
    # This documents the honest dormant behavior + guards against threading a
    # truthy sentinel that could false-match. (Grounded HIGH, being src_ip-only,
    # still works -- see test_scope_only_high_needs_attacker_ip_success.)
    result = {**_MODEL_OUTPUT, "src_ip": "45.61.53.10", "host": ""}
    rep = verifier.verify(result, scope_evidence=_CRIT_EV)   # has auth success + process-on-host claim
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
