# splunk-investigator/tests/test_eval_harness_import.py
"""Task 15: import-safety gate for the opt-in, PAID real-model
selection-quality eval harness (scripts/eval_selection.py).

The eval harness itself is never run by pytest (it is opt-in, USER-run,
paid -- see EVAL.md). This file only proves that IMPORTING it, reading its
module-level SCENARIOS, and building/driving its argparse-based main() via
the injected (offline) DI path never makes a real Anthropic call and never
needs ANTHROPIC_API_KEY -- so `pytest` collection alone can never trigger a
paid call, no matter which venv runs it.

Import mechanism mirrors tests/test_run_investigation.py's `from scripts
import run_investigation` (scripts/ is a package rootdir-inserted onto
sys.path the same way tests/ is).

Cross-venv note: this file imports ONLY splunk_investigator (+ anthropic,
to install a raising sentinel) -- never triage_verifier -- so it collects
and runs green under BOTH `splunk-investigator/.venv` and
`malware-triage/.venv` with no importorskip, unlike test_scenarios.py.
"""
from __future__ import annotations

import dataclasses
import importlib
import types

import pytest

from splunk_investigator.catalog import CATALOG
from splunk_investigator.config import load_config
from splunk_investigator.models import QueryResult
import splunk_investigator.agent as agent_mod

from scripts import eval_selection


def test_module_imports_without_error():
    # Reaching this line at all is the proof: the `from scripts import
    # eval_selection` above ran at pytest COLLECTION time, before any test
    # function executed, with no ANTHROPIC_API_KEY required in this test
    # environment. A module that built a real client at import time would
    # have blown up collection itself, never getting this far.
    assert eval_selection is not None


def test_scenarios_load_as_a_nonempty_list_of_well_formed_cases():
    scenarios = eval_selection.SCENARIOS
    assert isinstance(scenarios, list)
    assert len(scenarios) > 0

    required_alert_keys = {"src_ip", "host", "user", "event_time", "alert_text"}
    seen_names = set()
    for scenario in scenarios:
        assert isinstance(scenario.name, str) and scenario.name
        assert scenario.name not in seen_names, f"duplicate scenario name {scenario.name!r}"
        seen_names.add(scenario.name)

        assert isinstance(scenario.alert, dict)
        assert required_alert_keys.issubset(scenario.alert.keys())

        assert isinstance(scenario.expected_queries, (set, frozenset))
        assert len(scenario.expected_queries) > 0
        # Reuses the EXISTING v1 catalog only -- no new query, no query
        # that emits a fresh "ip" row field (controller notes SS3).
        assert scenario.expected_queries.issubset(CATALOG.keys())

        assert isinstance(scenario.expected_conclusion, bool)


def test_reload_with_no_api_key_and_a_raising_client_sentinel_never_trips_it(monkeypatch):
    """Prove no real client is constructed at import/collection: with
    ANTHROPIC_API_KEY unset AND anthropic.Anthropic monkeypatched to a
    sentinel that raises if instantiated, re-executing the module's
    top-level code (import) and reading SCENARIOS must both succeed
    without ever touching the sentinel."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def _boom(*a, **k):
        raise AssertionError("a real anthropic.Anthropic client must never be constructed at import")

    monkeypatch.setattr("anthropic.Anthropic", _boom, raising=False)

    reloaded = importlib.reload(eval_selection)
    assert len(reloaded.SCENARIOS) > 0


def test_main_injected_path_never_builds_a_live_client_even_with_no_api_key(monkeypatch):
    """main()'s injected path (both factories given) must stay fully
    offline -- it must never fall through to the live branch that builds
    anthropic.Anthropic() / a real splunklib Service, even if the eval
    harness is invoked directly (not just imported). repetitions=0 means
    run_eval's per-scenario loop body never runs, so this also does not
    depend on -- or exercise -- the scoring logic (that is covered
    separately, offline, below)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def _boom(*a, **k):
        raise AssertionError("main() must not build a live anthropic client when factories are injected")

    monkeypatch.setattr("anthropic.Anthropic", _boom, raising=False)

    rc = eval_selection.main(
        ["--repetitions", "0"],
        client_factory=lambda: object(),   # never touched: 0 repetitions
        service_factory=lambda: object(),
    )
    assert isinstance(rc, int)


def test_main_partial_factory_client_only_raises_before_live_branch(monkeypatch):
    # Passing exactly ONE factory is a caller bug -- it must fail loudly with
    # AssertionError, and it must fail BEFORE reaching the live branch that
    # would otherwise build a real anthropic.Anthropic() client. Prove the
    # latter by making that construction raise a distinguishable exception
    # (RuntimeError, not AssertionError) if it's ever reached.
    def _boom(*a, **k):
        raise RuntimeError("must not reach the live branch")

    monkeypatch.setattr("anthropic.Anthropic", _boom, raising=False)

    with pytest.raises(AssertionError, match="pass both factories or neither"):
        eval_selection.main(["--repetitions", "0"], client_factory=lambda: object(), service_factory=None)


def test_main_partial_factory_service_only_raises_before_live_branch(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("must not reach the live branch")

    monkeypatch.setattr("anthropic.Anthropic", _boom, raising=False)

    with pytest.raises(AssertionError, match="pass both factories or neither"):
        eval_selection.main(["--repetitions", "0"], client_factory=None, service_factory=lambda: object())


# --- optional (controller notes SS4d): exercise the scoring core fully
# offline, via a scripted client + a throwaway single-scenario list, to
# prove the harness's own scoring logic works before it is ever pointed at
# a real model. Decoupled from the real module-level SCENARIOS so it never
# needs updating when that list changes. ---------------------------------

class _StubClient:
    def __init__(self, script):
        self._script = list(script)
        self.messages = self

    def create(self, **kw):
        return self._script.pop(0)


def _tooluse(name, inp, tool_id="t1"):
    block = types.SimpleNamespace(type="tool_use", name=name, input=inp, id=tool_id)
    return types.SimpleNamespace(content=[block], stop_reason="tool_use",
                                 usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))


def test_run_eval_scores_an_offline_scripted_run(monkeypatch):
    alert = {
        "src_ip": "10.0.0.5", "host": "vm-honeypot-win", "user": "Administrator",
        "event_time": "2026-07-11T14:03:00", "alert_text": "test alert, not a real incident",
    }
    scenario = eval_selection.Scenario(
        name="offline_sanity_check",
        alert=alert,
        expected_queries=frozenset({"logon_outcomes_for_ip"}),
    )

    def _ok_auth(*a, **k):
        return QueryResult(query_name="logon_outcomes_for_ip", params={"ip": "10.0.0.5", "window": "-24h"},
                            outcome="ok", rows=({"success_count": "0", "fail_count": "3"},), row_count=1)

    monkeypatch.setattr(agent_mod, "run_catalog_query", _ok_auth)

    script = [
        _tooluse("logon_outcomes_for_ip", {"ip": "10.0.0.5", "window": "-24h"}),
        _tooluse("conclude_investigation", {"summary": "brute force, no success"}),
    ]
    cfg = dataclasses.replace(load_config(), max_queries=2, max_turns=5)

    report = eval_selection.run_eval(
        _StubClient(script), object(), cfg, scenarios=[scenario], repetitions=1, threshold=0.5,
    )

    assert report.total_runs == 1
    assert report.total_passes == 1
    assert report.passed is True
