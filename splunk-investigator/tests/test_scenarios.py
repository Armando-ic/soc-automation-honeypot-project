# splunk-investigator/tests/test_scenarios.py
"""Task 14: offline end-to-end scenario suite -- the correctness backbone.

Drives the real `investigate()` with a scripted Anthropic client + a
fixture-backed `run_catalog_query` stub (the stub routes every fixture
envelope through the REAL `parse_envelope`, so the error/capped/ok outcome
mapping is exercised, not hand-asserted). The resulting `scope_evidence` is
flattened exactly the way `grounding-service/grounding_service/app.py`
flattens it for the wire (that two-line transform is not importable --
inlined here per controller notes SS3/SS4), then fed together with a
hand-built triage `result` dict into `TriageVerifier.verify(...)` to assert
the gate outcome end to end. Fully offline: no network, no paid call, no
real Splunk connection -- `run_catalog_query` is monkeypatched at the
agent-module boundary (controller notes SS4 / interface map gotcha 5) and the
Anthropic client is a scripted stub (interface map SS5a).

Cross-package note (controller notes SS1, LOAD-BEARING): this file imports
both `splunk_investigator` and `triage_verifier`. Only `malware-triage/.venv`
has both installed -- `splunk-investigator/.venv` does not have
`triage_verifier`. The `pytest.importorskip` call below keeps this file
collectible (SKIPPED, not errored) under `splunk-investigator/.venv`, so the
standing `./.venv/Scripts/python -m pytest -q` run stays green. The
AUTHORITATIVE run for this file is
`cd splunk-investigator && ../malware-triage/.venv/Scripts/python -m pytest -q`,
where these scenarios actually execute.

These fixtures are hand-authored, labeled SYNTHETIC scenario data (not a
real attacker incident) -- see `fixtures/scenarios/README.md`.
"""
from __future__ import annotations

import dataclasses
import json
import types
from pathlib import Path

import pytest

pytest.importorskip("triage_verifier")

import triage_verifier
from triage_verifier.verifier import TriageVerifier

import splunk_investigator.agent as agent_mod
from splunk_investigator.agent import investigate
from splunk_investigator.config import load_config
from splunk_investigator.splunk_client import parse_envelope

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "scenarios"

# TriageVerifier is constructed from the installed triage_verifier package's
# own data files -- there is no shared conftest across packages (controller
# notes SS5).
_TV_ROOT = Path(triage_verifier.__file__).resolve().parent.parent
_SCHEMA = _TV_ROOT / "schema" / "submit_triage_result.json"
_DATA = _TV_ROOT / "data" / "attack_reference.json"


# --- DI stubs (mirrors test_agent.py / test_run_investigation.py) -----------

class _FakeSvc:
    """Never touched once run_catalog_query is stubbed -- any placeholder
    object works (interface map SS5b)."""


def _tooluse(name: str, inp: dict, tool_id: str = "t1"):
    block = types.SimpleNamespace(type="tool_use", name=name, input=inp, id=tool_id)
    return types.SimpleNamespace(content=[block], stop_reason="tool_use",
                                 usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))


class _ScriptedClient:
    """Returns a queued list of fake Messages responses (tool_use blocks)."""
    def __init__(self, script):
        self._script = list(script)
        self.messages = self

    def create(self, **kw):
        return self._script.pop(0)


# --- fixture loading ----------------------------------------------------------

def _load_alert(scenario: str) -> dict:
    return json.loads((_FIXTURES / scenario / "alert.json").read_text(encoding="utf-8"))


def _load_client(scenario: str) -> _ScriptedClient:
    turns = json.loads((_FIXTURES / scenario / "script.json").read_text(encoding="utf-8"))
    return _ScriptedClient([_tooluse(t["tool"], t["input"]) for t in turns])


def _envelope_dispatcher(scenario: str, recorder: list | None = None):
    """Fixture-backed `run_catalog_query` replacement: loads
    `<scenario>/<query_name>.json` (a Splunk output_mode=json envelope, same
    shape as `fixtures/envelopes/*.json`) and routes it through the REAL
    `parse_envelope` for outcome mapping (error/capped/ok precedence),
    per controller notes SS6 -- not hand-asserted.

    Matches the real `run_catalog_query(service, spl, query_name, params,
    result_cap, timeout_s)` signature exactly (interface map SS1/SS4), so it
    can be swapped in for `splunk_investigator.agent.run_catalog_query`
    (the agent-module-level name -- interface map gotcha 5) via monkeypatch.
    """
    def _dispatch(service, spl, query_name, params, result_cap, timeout_s):
        if recorder is not None:
            recorder.append({"query_name": query_name, "spl": spl, "params": dict(params)})
        raw = (_FIXTURES / scenario / f"{query_name}.json").read_bytes()
        return parse_envelope(raw, query_name, params, result_cap)
    return _dispatch


def _flat_scope_evidence(result) -> dict:
    # Inlined verbatim from grounding-service/grounding_service/app.py:263-264
    # (controller notes SS3 / interface map SS2) -- nothing importable does
    # this flatten; ScopeClaim stays nested (.type / .fields) everywhere
    # inside splunk_investigator itself.
    return {
        "claims": [{"type": c.type, **c.fields} for c in result.scope_evidence.claims],
        "queries_run": [dict(q) for q in result.scope_evidence.queries_run],
    }


def _cfg(**over):
    return dataclasses.replace(load_config(), max_queries=4, max_turns=10, **over)


# --- verifier + triage-result builders (mirrors test_scope_grounded.py) -----

@pytest.fixture(scope="module")
def verifier():
    return TriageVerifier.from_paths(_SCHEMA, _DATA)   # judge=None


def _status(report, check_name):
    result = next((r for r in report.results if r.name == check_name), None)
    return result.status.value if result is not None else None


_TRIAGE_BASE = {
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


def _triage_result(**over):
    base = dict(_TRIAGE_BASE)
    base["scope_findings"] = []
    base.update(over)
    return base


# ==============================================================================
# Scenario 1: success + encoded PowerShell escalates with grounded conjunction
# ==============================================================================

def test_success_plus_encoded_ps_escalates_with_grounded_conjunction(verifier, monkeypatch):
    scenario = "success_plus_encoded_ps"
    alert = _load_alert(scenario)
    client = _load_client(scenario)
    monkeypatch.setattr(agent_mod, "run_catalog_query", _envelope_dispatcher(scenario))

    result = investigate(alert, client=client, splunk_service=_FakeSvc(), cfg=_cfg())
    scope_ev = _flat_scope_evidence(result)

    auth_claim = next((c for c in scope_ev["claims"] if c["type"] == "auth_outcome"), None)
    ps_claim = next((c for c in scope_ev["claims"] if c["type"] == "encoded_powershell"), None)
    assert auth_claim is not None, "auth_outcome claim missing"
    assert ps_claim is not None, "encoded_powershell claim missing"
    assert auth_claim["success_count"] > 0
    assert ps_claim["count"] > 0

    triage = _triage_result(
        severity="critical",
        src_ip=alert["src_ip"],
        host=alert["host"],
        scope_findings=[auth_claim, ps_claim],
    )
    report = verifier.verify(triage, scope_evidence=scope_ev)
    assert _status(report, "severity_supported") == "passed"
    assert report.passed is True


# ==============================================================================
# Scenario 2: no success + no post-exploit -- minimal bundle, no inflation
# ==============================================================================

def test_no_success_no_postexploit_minimal_bundle_no_inflate(verifier, monkeypatch):
    scenario = "no_success_minimal"
    alert = _load_alert(scenario)
    client = _load_client(scenario)
    monkeypatch.setattr(agent_mod, "run_catalog_query", _envelope_dispatcher(scenario))

    result = investigate(alert, client=client, splunk_service=_FakeSvc(), cfg=_cfg())
    scope_ev = _flat_scope_evidence(result)

    # minimal bundle: exactly the one auth_outcome claim (a real 0-row
    # negative), nothing manufactured for process/encoded activity that was
    # never queried.
    assert [c["type"] for c in scope_ev["claims"]] == ["auth_outcome"]
    assert scope_ev["claims"][0]["success_count"] == 0

    triage = _triage_result(severity="high", src_ip=alert["src_ip"])
    report = verifier.verify(triage, scope_evidence=scope_ev)
    assert _status(report, "severity_supported") == "failed"
    assert report.passed is False


# ==============================================================================
# Scenario 3: a lone success supports "high", not "critical"
# ==============================================================================

def test_lone_success_supports_high_not_critical(verifier, monkeypatch):
    scenario = "lone_success"
    alert = _load_alert(scenario)
    client = _load_client(scenario)
    monkeypatch.setattr(agent_mod, "run_catalog_query", _envelope_dispatcher(scenario))

    result = investigate(alert, client=client, splunk_service=_FakeSvc(), cfg=_cfg())
    scope_ev = _flat_scope_evidence(result)

    assert [c["type"] for c in scope_ev["claims"]] == ["auth_outcome"]
    assert scope_ev["claims"][0]["success_count"] == 1

    critical = _triage_result(severity="critical", src_ip=alert["src_ip"], host=alert["host"])
    critical_report = verifier.verify(critical, scope_evidence=scope_ev)
    assert _status(critical_report, "severity_supported") == "failed"

    high = _triage_result(severity="high", src_ip=alert["src_ip"])
    high_report = verifier.verify(high, scope_evidence=scope_ev)
    assert _status(high_report, "severity_supported") == "passed"


# ==============================================================================
# Scenario 4: a soft-error query is UNKNOWN, not a proven negative
#
# BRIEF WORDING CORRECTED (controller notes SS7.4): the brief's literal text
# ("assert the query_error flag is set" / "a note claiming 'no successful
# logon' is caught by scope_notes_honesty") does not match shipped code --
# there is no query_error flag (agent.py only ever sets max_turns_reached /
# claude_outage / agent_error), and scope_notes_honesty deliberately SKIPS
# negated sentences ("no successful logon" is a negation, never flagged).
# The faithful test of the real intent below: (a) an errored query emits NO
# claim and never appears in queries_run, contrasted with (b) an ok+0-row
# query, which DOES emit a real negative claim and IS recorded -- pinning
# the absence-vs-unknown distinction; then (c) an UNBACKED POSITIVE note
# ("Confirmed successful logon...") is still caught by scope_notes_honesty,
# proving an unknown query can't be laundered into a positive conclusion.
# ==============================================================================

def test_soft_error_query_is_not_read_as_absence(verifier, monkeypatch):
    # (a) FATAL envelope -> outcome="error" -> no claim, absent from queries_run.
    fatal_scenario = "soft_error_fatal"
    fatal_alert = _load_alert(fatal_scenario)
    fatal_client = _load_client(fatal_scenario)
    monkeypatch.setattr(agent_mod, "run_catalog_query", _envelope_dispatcher(fatal_scenario))
    fatal_result = investigate(fatal_alert, client=fatal_client, splunk_service=_FakeSvc(), cfg=_cfg())
    fatal_scope = _flat_scope_evidence(fatal_result)

    assert fatal_scope["claims"] == []
    assert fatal_scope["queries_run"] == []

    # (b) contrast: ok + 0 rows IS a real negative finding -- emits a claim
    # and IS recorded in queries_run. Same query, same shape alert, only the
    # envelope outcome differs.
    zero_scenario = "soft_error_ok_zero"
    zero_alert = _load_alert(zero_scenario)
    zero_client = _load_client(zero_scenario)
    monkeypatch.setattr(agent_mod, "run_catalog_query", _envelope_dispatcher(zero_scenario))
    zero_result = investigate(zero_alert, client=zero_client, splunk_service=_FakeSvc(), cfg=_cfg())
    zero_scope = _flat_scope_evidence(zero_result)

    assert [c["type"] for c in zero_scope["claims"]] == ["auth_outcome"]
    assert zero_scope["claims"][0]["success_count"] == 0
    assert len(zero_scope["queries_run"]) == 1

    # (c) an UNBACKED POSITIVE conclusion after a soft-errored query must be
    # caught -- and the catch must be CONTINGENT on the errored (empty-claims)
    # scope_evidence, not true-by-construction. So we hand the triage a
    # fabricated scope_finding that WOULD ground field-for-field against a
    # real success claim (exact key-SET {type, ip, user, success_count,
    # fail_count} matching the flat auth_outcome shape) plus the same
    # "Confirmed successful logon" note. Against the fatal run's EMPTY claims
    # the finding grounds nothing, so both gates fail closed; against a
    # constructed success scope whose claim exactly equals that finding, both
    # gates pass. The delta between the two proves the failures are caused by
    # the query having errored, not by the test never populating
    # scope_findings.
    fabricated_finding = {
        "type": "auth_outcome",
        "ip": fatal_alert["src_ip"],
        "user": None,
        "success_count": 1,
        "fail_count": 0,
    }
    note = f"Confirmed successful logon from {fatal_alert['src_ip']}."

    # against the errored scope (empty claims): fabricated finding grounds
    # nothing -> both gates fail closed.
    errored_triage = _triage_result(
        severity="low",
        src_ip=fatal_alert["src_ip"],
        investigation_notes=note,
        scope_findings=[fabricated_finding],
    )
    errored_report = verifier.verify(errored_triage, scope_evidence=fatal_scope)
    assert _status(errored_report, "scope_findings_grounded") == "failed"
    assert _status(errored_report, "scope_notes_honesty") == "failed"

    # contrast: a constructed success scope whose auth_outcome claim EXACTLY
    # equals the fabricated finding -> the finding grounds, the positive note
    # is backed -> both gates pass. Same triage inputs, only the scope_evidence
    # differs, so this isolates the errored-query cause above.
    success_scope = {
        "claims": [dict(fabricated_finding)],
        "queries_run": [{
            "query": "logon_outcomes_for_ip",
            "params": {"ip": fatal_alert["src_ip"], "window": "-24h"},
            "outcome": "ok",
            "row_count": 1,
        }],
    }
    success_triage = _triage_result(
        severity="low",
        src_ip=fatal_alert["src_ip"],
        investigation_notes=note,
        scope_findings=[dict(fabricated_finding)],
    )
    success_report = verifier.verify(success_triage, scope_evidence=success_scope)
    assert _status(success_report, "scope_findings_grounded") == "passed"
    assert _status(success_report, "scope_notes_honesty") == "passed"


# ==============================================================================
# Scenario 5: alert-text injection cannot steer the model off the catalog
# ==============================================================================

def test_injection_alert_text_cannot_steer_off_catalog(verifier, monkeypatch):
    scenario = "injection"
    alert = _load_alert(scenario)
    client = _load_client(scenario)
    recorder: list[dict] = []
    monkeypatch.setattr(agent_mod, "run_catalog_query", _envelope_dispatcher(scenario, recorder=recorder))

    result = investigate(alert, client=client, splunk_service=_FakeSvc(), cfg=_cfg())
    scope_ev = _flat_scope_evidence(result)

    # no claim ever references the off-scope IP seeded in alert_text, or the
    # malicious user string -- params.py's entity-binding/charset gate must
    # have rejected both attempts before a claim could ever be derived.
    off_scope_ip = "8.8.8.8"
    malicious_user = "; | delete"
    assert not any(c.get("ip") == off_scope_ip for c in scope_ev["claims"])
    assert not any(c.get("user") == malicious_user for c in scope_ev["claims"])

    # exactly one call reached run_catalog_query (the single legit in-scope
    # query) -- the two off-scope/malicious attempts were rejected by
    # render_spl's param validation BEFORE run_catalog_query is ever called,
    # so they never even reach this fixture dispatcher.
    assert len(recorder) == 1
    for call in recorder:
        assert off_scope_ip not in call["spl"]
        assert call["params"].get("ip") != off_scope_ip
        assert call["params"].get("user") != malicious_user
        for disallowed_op in ("| delete", "| outputlookup", "| collect", "| script"):
            assert disallowed_op not in call["spl"]
