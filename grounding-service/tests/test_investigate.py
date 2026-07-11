"""Phase 4 Task 11: POST /investigate must NEVER 500 and degrades to the
well-typed empty result on any failure (spec section 2.1). Mirrors
test_deobfuscate.py's app-build style (injected factory stubs via
create_app), but /investigate's guarantee is stronger: the WHOLE handler
body is wrapped in a catch-all, not just the client factory call."""
import types

from fastapi.testclient import TestClient

from grounding_service.app import create_app
from grounding_service.config import Settings

EMPTY_SCOPE_EVIDENCE = {"claims": [], "queries_run": []}


def _client(seeded_retriever, tmp_path, investigation_factory=None, splunk_factory=None):
    s = Settings(runs_path=str(tmp_path / "runs.jsonl"))
    return TestClient(create_app(
        seeded_retriever, s,
        investigation_client_factory=investigation_factory,
        splunk_service_factory=splunk_factory,
    ))


def test_no_pivot_returns_well_typed_empty(seeded_retriever, tmp_path):
    # No host and no public src_ip -- the pregate's "no_pivot" short-circuit
    # fires BEFORE any client/service is even touched (no factories injected
    # here at all -- this must not matter, since the pregate wins first).
    c = _client(seeded_retriever, tmp_path)
    resp = c.post("/investigate", json={"alert": {"src_ip": "", "host": ""}})
    body = resp.json()
    assert resp.status_code == 200
    assert body["investigated"] is False
    assert body["scope_evidence"] == EMPTY_SCOPE_EVIDENCE
    assert body["flags"] == ["no_pivot"]
    assert body["advisory_reasoning"] == ""


def test_engine_exception_degrades_to_empty_never_500(seeded_retriever, tmp_path):
    # A pivotable alert (public src_ip + host) clears the pregate, but the
    # investigation_client_factory itself raises (mirrors test_deobfuscate's
    # `boom()` outage-guard style) -- must degrade to the well-typed empty
    # result, never 500, and investigated must stay False (no half-run).
    def boom():
        raise RuntimeError("no key")

    c = _client(seeded_retriever, tmp_path, investigation_factory=boom, splunk_factory=lambda: object())
    resp = c.post("/investigate", json={
        "alert": {"src_ip": "45.61.53.10", "host": "h", "event_time": "2026-07-11T14:03:00"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigated"] is False
    assert body["scope_evidence"] == EMPTY_SCOPE_EVIDENCE


def test_splunk_service_outage_degrades_to_empty_never_500(seeded_retriever, tmp_path):
    # Same class of outage, but on the OTHER factory (splunk_service_factory
    # raises, client factory succeeds) -- proves both factories are guarded
    # independently, not just the Claude one.
    def boom():
        raise RuntimeError("no splunk creds")

    c = _client(seeded_retriever, tmp_path, investigation_factory=lambda: object(), splunk_factory=boom)
    resp = c.post("/investigate", json={
        "alert": {"src_ip": "45.61.53.10", "host": "h", "event_time": "2026-07-11T14:03:00"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigated"] is False
    assert body["scope_evidence"] == EMPTY_SCOPE_EVIDENCE


def test_factories_not_wired_degrades_to_empty_not_none_client(seeded_retriever, tmp_path):
    # Neither factory injected (both None, the create_app default) -- a
    # pivotable alert must NOT reach run_investigation() with a None
    # client/service; it degrades to empty with a flag instead.
    c = _client(seeded_retriever, tmp_path)
    resp = c.post("/investigate", json={
        "alert": {"src_ip": "45.61.53.10", "host": "h", "event_time": "2026-07-11T14:03:00"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigated"] is False
    assert body["scope_evidence"] == EMPTY_SCOPE_EVIDENCE


def _tooluse(name, inp, tool_id="t1"):
    block = types.SimpleNamespace(type="tool_use", name=name, input=inp, id=tool_id)
    return types.SimpleNamespace(content=[block], stop_reason="tool_use",
                                  usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))


class _StubClient:
    """Same shape as splunk-investigator's test_agent.py _StubClient: a
    queued list of fake Messages responses (tool_use blocks)."""
    def __init__(self, script):
        self._script = list(script)
        self.messages = self

    def create(self, **kw):
        return self._script.pop(0)


class _StubService:
    """Never actually touched -- run_catalog_query is monkeypatched below."""


def test_pivotable_alert_runs_investigation_and_serializes_claims_flat(seeded_retriever, tmp_path, monkeypatch):
    # LOAD-BEARING cross-task contract: each ScopeClaim must serialize FLAT
    # as {"type": c.type, **c.fields}, NOT nested under a "fields" key --
    # Task 10's verifier does field-for-field equality against this exact
    # shape. This is the positive path proving the endpoint actually wires
    # should_investigate -> investigate() -> the flat response shape.
    from splunk_investigator.models import QueryResult

    def _fake_run_catalog_query(*a, **k):
        return QueryResult(
            query_name="logon_outcomes_for_ip",
            params={"ip": "45.61.53.10", "window": "-24h"},
            outcome="ok",
            rows=({"success_count": "0", "fail_count": "12"},),
            row_count=1,
        )

    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", _fake_run_catalog_query)

    script = [
        _tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
        _tooluse("conclude_investigation", {"summary": "brute force only, no successful logons"}),
    ]
    c = _client(
        seeded_retriever, tmp_path,
        investigation_factory=lambda: _StubClient(script),
        splunk_factory=lambda: _StubService(),
    )
    resp = c.post("/investigate", json={
        "alert": {"src_ip": "45.61.53.10", "host": "vm-honeypot-win",
                  "event_time": "2026-07-11T14:03:00", "alert_text": "brute force"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigated"] is True
    assert body["scope_evidence"]["claims"] == [{
        "type": "auth_outcome", "ip": "45.61.53.10", "user": None,
        "success_count": 0, "fail_count": 12,
    }]
    assert body["scope_evidence"]["queries_run"] == [{
        "query": "logon_outcomes_for_ip",
        "params": {"ip": "45.61.53.10", "window": "-24h"},
        "outcome": "ok",
        "row_count": 1,
    }]
    assert body["advisory_reasoning"] == "brute force only, no successful logons"


def test_malformed_alert_does_not_500(seeded_retriever, tmp_path):
    # A structurally-odd alert (missing every key the pregate/agent expect)
    # must still 200 -> empty, not 500. Proves the catch-all around the
    # WHOLE handler body, not just the two factory calls.
    c = _client(seeded_retriever, tmp_path)
    resp = c.post("/investigate", json={"alert": {}})
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigated"] is False
    assert body["scope_evidence"] == EMPTY_SCOPE_EVIDENCE
