# splunk-investigator/tests/test_run_investigation.py
"""Task 9: the DI CLI runner must run the whole investigation loop OFFLINE
(no network, no paid call) when factories are injected. Mirrors
malware-triage/tests/test_run_triage.py's shape: a scripted stub client
(queued tool_use responses, Phase-3/Task-7 stub style) + a stub Splunk
service, both supplied via factories, with run_catalog_query monkeypatched
so no real Splunk connection is ever attempted."""
import types

from scripts import run_investigation
from splunk_investigator.models import QueryResult
from splunk_investigator.report import GROUNDED_HEADER


class _StubClient:
    """Returns a queued list of fake Messages responses (tool_use blocks).
    Same shape as test_agent.py's _StubClient."""
    def __init__(self, script):
        self._script = list(script)
        self.messages = self

    def create(self, **kw):
        return self._script.pop(0)


class _StubService:
    """Never actually touched -- run_catalog_query is monkeypatched below,
    so this stands in for a real splunklib.client.Service without ever
    making a network call."""
    pass


def _tooluse(name, inp, tool_id="t1"):
    block = types.SimpleNamespace(type="tool_use", name=name, input=inp, id=tool_id)
    return types.SimpleNamespace(content=[block], stop_reason="tool_use",
                                 usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))


def _mk_ok_auth():
    return QueryResult(query_name="logon_outcomes_for_ip", params={"ip": "45.61.53.10", "window": "-24h"},
                        outcome="ok", rows=({"success_count": "0", "fail_count": "12"},), row_count=1)


def _script():
    return [
        _tooluse("logon_outcomes_for_ip", {"ip": "45.61.53.10", "window": "-24h"}),
        _tooluse("conclude_investigation", {"summary": "brute force only, no successful logons"}),
    ]


def test_main_returns_0_and_prints_grounded_header_offline(monkeypatch, capsys):
    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_ok_auth())

    rc = run_investigation.main(
        [],
        client_factory=lambda: _StubClient(_script()),
        service_factory=lambda: _StubService(),
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert GROUNDED_HEADER in out


def test_main_offline_path_never_builds_a_real_client_or_service(monkeypatch, capsys):
    # Prove the injected path is fully offline: if main() ever tried to build
    # a real anthropic client or a real splunk connection on this path, this
    # would raise (no ANTHROPIC_API_KEY / no live Splunk in this test env) --
    # blow up main() with a sentinel exception instead of silently passing.
    def _boom():
        raise AssertionError("main() must not build a live client/service when factories are injected")

    monkeypatch.setattr("splunk_investigator.agent.run_catalog_query", lambda *a, **k: _mk_ok_auth())
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: _boom(), raising=False)

    rc = run_investigation.main(
        [],
        client_factory=lambda: _StubClient(_script()),
        service_factory=lambda: _StubService(),
    )
    assert rc == 0


def test_run_investigation_core_renders_full_report():
    monkeypatch_result = None  # not needed here; call the pure core directly
    import dataclasses
    from splunk_investigator.config import load_config

    cfg = dataclasses.replace(load_config(), max_queries=2, max_turns=5)

    class _Client(_StubClient):
        pass

    # run_catalog_query is agent-module-level; patch it directly for this test.
    import splunk_investigator.agent as agent_mod
    orig = agent_mod.run_catalog_query
    agent_mod.run_catalog_query = lambda *a, **k: _mk_ok_auth()
    try:
        md = run_investigation.run_investigation(
            run_investigation.DEMO_ALERT,
            client=_Client(_script()),
            splunk_service=_StubService(),
            cfg=cfg,
        )
    finally:
        agent_mod.run_catalog_query = orig

    assert GROUNDED_HEADER in md
    assert "brute-force" in md.lower() or "auth_outcome" in md
