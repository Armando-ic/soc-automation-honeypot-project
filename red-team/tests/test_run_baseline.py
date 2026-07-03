from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from red_team.cases import AttackCase
from red_team.harness.model_client import ModelClient
from red_team.harness.system_prompt import load_system_prompt, load_tool_def
from red_team.report import build_baseline_report
from triage_verifier.verifier import TriageVerifier
from tests.conftest import REPO

from scripts.run_baseline import main, parse_headline, run_campaign


def _verifier():
    return TriageVerifier.from_paths(
        REPO / "triage-verifier/schema/submit_triage_result.json",
        REPO / "triage-verifier/data/attack_reference.json")


def _resp(blocks, stop_reason="tool_use"):
    return SimpleNamespace(content=blocks, stop_reason=stop_reason,
                           usage=SimpleNamespace(input_tokens=1, output_tokens=1))


def _tool_use(inp):
    return SimpleNamespace(type="tool_use", name="submit_triage_result", input=inp)


def _under_escalated():
    return {"schema_version": "v1", "alert_summary": "x", "severity": "medium",
            "severity_rationale": "x", "mitre_techniques": [], "iocs": {"ips": [], "domains": [],
            "file_hashes": [], "users": [], "hosts": []}, "iocs_enriched": [],
            "recommended_actions": [{"description": "x", "priority": "low"}], "investigation_notes": "x"}


def _case(cid):
    # Mirrors test_runner._a1_case: retrieval="real" so run_case exercises the
    # seeded_retriever fixture, never the live BgeEmbedder/QdrantClient path.
    return AttackCase(id=cid, class_="LLM01", atlas="", source="splunk",
                      alert={"search_name": "RDP brute force", "src_ip": "192.0.2.1",
                             "user": "Administrator", "ComputerName": "h", "count": "240"},
                      fixed_enrichment={"192.0.2.1": "malicious"}, retrieval="real",
                      fixed_techniques=None, objective="", expected_correct={"severity": "high"},
                      win_condition=["severity_below_expected"])


def _mock_client():
    client = MagicMock()
    client.messages.create.return_value = _resp([_tool_use(_under_escalated())])
    return client


def test_call_shape_matches_deployed_node_exactly(seeded_retriever):
    """Permanent Step-2 gate: the exact kwarg set sent to messages.create, built
    the way main() builds ModelClient (real system prompt / tool def)."""
    client = _mock_client()
    mc = ModelClient(client, system=load_system_prompt(), tool=load_tool_def())
    run_campaign([_case("A1-x")], mc, seeded_retriever, _verifier(),
                  k_default=1, headline={}, progress=lambda *a, **k: None)

    client.messages.create.assert_called_once()
    kwargs = client.messages.create.call_args.kwargs
    assert set(kwargs.keys()) == {"model", "max_tokens", "system", "tools", "messages"}
    for forbidden in ("tool_choice", "temperature", "top_p", "top_k", "thinking", "effort"):
        assert forbidden not in kwargs


def test_run_campaign_applies_per_class_headline_k(seeded_retriever):
    client = _mock_client()
    mc = ModelClient(client, system="s", tool={"name": "submit_triage_result", "input_schema": {}})
    cases = [_case("A2-x"), _case("C1-x")]
    results = run_campaign(cases, mc, seeded_retriever, _verifier(),
                            k_default=5, headline={"A2": 50}, progress=lambda *a, **k: None)
    by_id = {r.case.id: r for r in results}
    assert by_id["A2-x"].k == 50
    assert len(by_id["A2-x"].trials) == 50
    assert by_id["C1-x"].k == 5
    assert len(by_id["C1-x"].trials) == 5


def test_report_aggregates_campaign_results(seeded_retriever):
    client = _mock_client()
    mc = ModelClient(client, system="s", tool={"name": "submit_triage_result", "input_schema": {}})
    results = run_campaign([_case("A2-x")], mc, seeded_retriever, _verifier(),
                            k_default=3, headline={}, progress=lambda *a, **k: None)
    md = build_baseline_report(results)
    assert "## A2" in md
    assert "Model-deviation rate" in md


@pytest.mark.parametrize("spec, expected", [
    ("A2:50,B1:30", {"A2": 50, "B1": 30}),
    ("", {}),
    (None, {}),
])
def test_parse_headline(spec, expected):
    assert parse_headline(spec) == expected


def test_parse_headline_rejects_malformed_token():
    with pytest.raises(ValueError):
        parse_headline("A2:fifty")


def test_dry_run_makes_zero_live_calls_needs_no_key_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out_file = tmp_path / "baseline-dryrun.md"

    main(["--dry-run", "--out", str(out_file)])

    assert not out_file.exists()
