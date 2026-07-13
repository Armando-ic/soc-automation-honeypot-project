# splunk-investigator/tests/test_agent.py
from splunk_investigator.agent import investigate, build_tools
from splunk_investigator.config import load_config
from splunk_investigator.models import QueryResult
import dataclasses

CFG = dataclasses.replace(load_config(), max_queries=2, max_turns=5)
ALERT = {"src_ip": "45.61.53.10", "host": "vm-honeypot-win", "user": "Administrator",
         "event_time": "2026-07-11T14:03:00", "alert_text": "brute force"}


class _StubClient:
    """Returns a queued list of fake Messages responses (tool_use blocks)."""
    def __init__(self, script): self._script = list(script); self.messages = self
    def create(self, **kw):
        return self._script.pop(0)


class _RecordingStubClient:
    """Like _StubClient but also records every kwargs dict passed to create().
    Used only by the bonus MAX_QUERIES-forcing test below, to prove the force
    is real (inspects what create() actually received), not just that the
    loop happens to terminate."""
    def __init__(self, script): self._script = list(script); self.calls = []; self.messages = self
    def create(self, **kw):
        self.calls.append(kw)
        return self._script.pop(0)


class _FakeSvc:  # run_catalog_query is injected; here we stub the service call layer
    pass


def _tooluse(name, inp, tool_id="t1"):
    import types
    block = types.SimpleNamespace(type="tool_use", name=name, input=inp, id=tool_id)
    return types.SimpleNamespace(content=[block], stop_reason="tool_use",
                                 usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))


def _mk_ok_auth():
    return QueryResult(query_name="logon_outcomes_for_ip", params={"ip": "45.61.53.10", "window": "-24h"},
                        outcome="ok", rows=({"success_count": "1", "fail_count": "0"},), row_count=1)


def _mk_zero_auth():
    return QueryResult(query_name="logon_outcomes_for_ip", params={"ip": "45.61.53.10", "window": "-24h"},
                        outcome="ok", rows=({"success_count": "0", "fail_count": "12"},), row_count=1)


def test_conclude_ends_loop(monkeypatch):
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query",
                        lambda *a, **k: _mk_ok_auth())
    script = [_tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
              _tooluse("conclude_investigation", {"summary": "done"})]
    r = investigate(ALERT, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    assert r.investigated is True
    assert any(c.type == "auth_outcome" for c in r.scope_evidence.claims)


def test_max_turns_terminates_a_never_concluding_loop(monkeypatch):
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_ok_auth())
    # a client that always asks for the SAME query (cached dup) never concludes
    always = [_tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"})] * 50
    r = investigate(ALERT, client=_StubClient(always), splunk_service=_FakeSvc(), cfg=CFG)
    assert r.investigated is True                       # terminated, did not hang
    # PRE-FLIGHT FIX (controller-authorized): the brief's literal line here was
    # `assert "capped" in r.flags or True` -- a tautology (the `or True` makes
    # it always pass, proving nothing). Replaced with a real assertion on the
    # NAMED flag the loop actually sets when it hits MAX_TURNS without
    # concluding -- this is what actually proves bounded termination.
    assert "max_turns_reached" in r.flags


def test_off_scope_param_returns_tool_error_not_crash(monkeypatch):
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_ok_auth())
    script = [_tooluse("logon_outcomes_for_ip", {"ip": "8.8.8.8", "window": "-24h"}),
              _tooluse("conclude_investigation", {"summary": "done"})]
    r = investigate(ALERT, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    assert not any(c.fields.get("ip") == "8.8.8.8" for c in r.scope_evidence.claims)


# --- Step 5 required cases (brief) ---

def test_conclude_on_first_turn_yields_empty_claims_bundle():
    script = [_tooluse("conclude_investigation", {"summary": "nothing to see"})]
    r = investigate(ALERT, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    assert r.investigated is True
    assert r.scope_evidence.claims == ()
    assert r.advisory_reasoning == "nothing to see"


def test_claude_outage_degrades_to_bounded_result():
    class _RaisingClient:
        def __init__(self): self.messages = self
        def create(self, **kw): raise RuntimeError("simulated Claude outage")

    r = investigate(ALERT, client=_RaisingClient(), splunk_service=_FakeSvc(), cfg=CFG)
    assert "claude_outage" in r.flags
    assert r.investigated is True
    assert r.scope_evidence.claims == ()


def test_transcript_shows_the_skip_when_model_declines_followup(monkeypatch):
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_zero_auth())
    script = [_tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
              _tooluse("conclude_investigation", {"summary": "brute force only, no successful logons"})]
    r = investigate(ALERT, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    tools_run = {t["tool"] for t in r.transcript if t["tool"]}
    assert tools_run == {"logon_outcomes_for_ip", "conclude_investigation"}
    assert "processes_by_user" not in tools_run


def test_transcript_result_is_rows_free_for_publication(monkeypatch):
    # The transcript is surfaced verbatim in the /investigate HTTP response and
    # is a capture-for-publication surface (Task 17 deliverable #3). Each query
    # turn's `result` must carry the decision trace (outcome + row_count) but NOT
    # the raw Splunk rows: rows can include attacker-influenced free-text (a
    # Sysmon image/user) that the claims path sanitizes, plus fields the grounded
    # claims drop. row_count conveys "N rows"; the grounded claims carry the
    # values. The full rows stay IN-LOOP as the model's tool_result (the model
    # needs them) but must never reach this published surface.
    import json
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_zero_auth())
    script = [_tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
              _tooluse("conclude_investigation", {"summary": "brute force only"})]
    r = investigate(ALERT, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    query_turns = [t for t in r.transcript if t["tool"] == "logon_outcomes_for_ip"]
    assert query_turns, "expected the query turn in the transcript"
    for t in query_turns:
        parsed = json.loads(t["result"])
        assert set(parsed.keys()) == {"outcome", "row_count"}   # no "rows" key
        assert parsed == {"outcome": "ok", "row_count": 1}
    # belt-and-suspenders: the raw row value ("fail_count"/"12") must not appear
    # anywhere in any transcript entry's result string.
    joined = "".join(str(t.get("result", "")) for t in r.transcript)
    assert "fail_count" not in joined and '"rows"' not in joined


# --- coverage added beyond the brief: MAX_QUERIES is the paid-cost bound this
# whole task exists to prove; verify the FORCE is real (inspect what create()
# actually received on the NEXT call), not just that the loop happens to
# terminate. ---

def test_max_queries_forces_conclude_tool_choice(monkeypatch):
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_ok_auth())
    script = [
        _tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
        _tooluse("user_targets_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
        _tooluse("conclude_investigation", {"summary": "done"}),
    ]
    client = _RecordingStubClient(script)
    r = investigate(ALERT, client=client, splunk_service=_FakeSvc(), cfg=CFG)
    assert r.investigated is True
    # CFG.max_queries == 2: after the 2nd DISTINCT successful query, the THIRD
    # create() call must be forced to conclude_investigation -- not merely
    # "the model happened to pick it".
    assert client.calls[2]["tool_choice"] == {"type": "tool", "name": "conclude_investigation"}


def test_build_tools_includes_every_catalog_query_plus_conclude():
    from splunk_investigator.catalog import CATALOG
    tools = build_tools()
    names = {t["name"] for t in tools}
    assert names == set(CATALOG) | {"conclude_investigation"}
    conclude = next(t for t in tools if t["name"] == "conclude_investigation")
    assert conclude["input_schema"]["required"] == ["summary"]


# --- LB-1: epoch event_time (the live saved-search shape) must still anchor
# time-bounded queries. Without the normalizer the agent hands render_spl a
# bare epoch string -> fromisoformat raises -> render_error -> NO claim, which
# is exactly the "grounding inert in production" blocker. ---

def test_epoch_event_time_still_anchors_time_bounded_query(monkeypatch):
    captured = {}

    def _fake_run(service, spl, name, inp, cap, timeout):
        captured["spl"] = spl
        return _mk_ok_auth()

    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", _fake_run)
    # epoch seconds, NOT ISO -- what `earliest(_time)`/`latest(_time)` emit.
    alert = dict(ALERT, event_time="1751500800")
    script = [_tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
              _tooluse("conclude_investigation", {"summary": "done"})]
    r = investigate(alert, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    # A claim was produced -> render_spl SUCCEEDED on the epoch event_time.
    assert any(c.type == "auth_outcome" for c in r.scope_evidence.claims)
    # ...and the rendered SPL carries real anchored bounds (not now, not empty).
    assert "earliest=" in captured["spl"] and "latest=" in captured["spl"]


def test_unparseable_event_time_still_fails_closed_no_claim(monkeypatch):
    # Fail-safe must survive the normalizer: genuinely-unparseable event_time
    # -> '' -> render_error on time-bounded queries -> no claim, no crash.
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_ok_auth())
    alert = dict(ALERT, event_time="not-a-timestamp")
    script = [_tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
              _tooluse("conclude_investigation", {"summary": "done"})]
    r = investigate(alert, client=_StubClient(script), splunk_service=_FakeSvc(), cfg=CFG)
    assert r.investigated is True
    assert not any(c.type == "auth_outcome" for c in r.scope_evidence.claims)
