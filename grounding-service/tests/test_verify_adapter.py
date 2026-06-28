import json
from unittest.mock import MagicMock

from grounding_service.config import Settings
from grounding_service.verify_adapter import build_report

GOOD = {
    "schema_version": "v1", "alert_summary": "x", "severity": "low", "severity_rationale": "x",
    "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "credential-access"}],
    "iocs": {"ips": ["203.0.113.10"], "domains": [], "file_hashes": [], "users": [], "hosts": []},
    "iocs_enriched": [{"value": "203.0.113.10", "ioc_type": "ip", "verdict": "malicious",
                       "source": "abuseipdb", "summary": "x"}],
    "recommended_actions": [{"description": "block", "priority": "high"}],
    "investigation_notes": "x",
}
META = {"run_id": "r1", "timestamp": "2026-06-27T00:00:00Z", "tokens_in": 10,
        "tokens_out": 20, "latency_ms": 100}


def _settings(tmp_path) -> Settings:
    return Settings(runs_path=str(tmp_path / "runs.jsonl"))


def test_report_passes_and_logs(tmp_path):
    s = _settings(tmp_path)
    rep = build_report(GOOD, retrieved=["T1110"],
                       enrichment_results={"203.0.113.10": "malicious"}, run_meta=META, settings=s)
    assert rep["verification_passed"] is True
    names = {c["name"]: c["status"] for c in rep["check_results"]}
    assert names["mitre_in_retrieved"] == "passed"       # deferred check now live
    assert names["enrichment_grounded"] == "passed"      # deferred check now live
    assert names["judge"] == "needs_human"               # StubJudge (no client)
    lines = (tmp_path / "runs.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["run_id"] == "r1"


def test_retrieved_mismatch_fails(tmp_path):
    rep = build_report(GOOD, retrieved=["T9999"],
                       enrichment_results={"203.0.113.10": "malicious"}, run_meta=META,
                       settings=_settings(tmp_path))
    assert rep["verification_passed"] is False


def test_claude_client_used_when_supplied(tmp_path):
    client = MagicMock()
    client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="advisory note")])
    rep = build_report(GOOD, retrieved=["T1110"],
                       enrichment_results={"203.0.113.10": "malicious"}, run_meta=META,
                       settings=_settings(tmp_path), client=client)
    client.messages.create.assert_called_once()
    judge = next(c for c in rep["check_results"] if c["name"] == "judge")
    assert judge["status"] == "needs_human"
    assert "advisory note" in judge["detail"]


def test_verifier_exception_gates_false_and_logs(tmp_path, monkeypatch):
    s = _settings(tmp_path)
    # Force the verifier to blow up at construction (covers the wrapped call).
    from grounding_service import verify_adapter

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(verify_adapter.TriageVerifier, "from_paths", boom)

    rep = build_report(GOOD, retrieved=["T1110"],
                       enrichment_results={"203.0.113.10": "malicious"}, run_meta=META, settings=s)

    assert rep["verification_passed"] is False
    assert "verifier_error" in [c["name"] for c in rep["check_results"]]
    lines = (tmp_path / "runs.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1                                   # event logged, never dropped
    assert json.loads(lines[0])["verification_passed"] is False
