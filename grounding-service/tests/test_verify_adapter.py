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


def test_build_report_gates_a_prompt_leak(tmp_path):
    # A result whose notes disclose >=3 distinct compound schema fields must
    # produce verification_passed == False via the new C1 gate.
    leaky = {
        "schema_version": "v1", "alert_summary": "x", "severity": "low",
        "severity_rationale": "x", "mitre_techniques": [], "iocs": {},
        "iocs_enriched": [], "recommended_actions": [{"description": "x", "priority": "low"}],
        "investigation_notes": "Fields: investigation_notes, iocs_enriched, mitre_techniques disclosed.",
    }
    settings = Settings(runs_path=str(tmp_path / "runs.jsonl"))
    rec = build_report(leaky, retrieved=None, enrichment_results=None, run_meta={}, settings=settings)
    assert rec["verification_passed"] is False
    names = {c["name"]: c["status"] for c in rec["check_results"]}
    assert names.get("notes_no_config_leak") == "failed"


# A sentinel prompt line that (a) is >=24 chars, (b) is NOT a severity-band line
# (doesn't start with low/medium/high/critical:), and (c) does NOT appear in the
# real deployed JSON/honeypot-triage.json. The ONLY way the C1 gate can fire on
# notes carrying this line — with <3 distinct compound schema field names present —
# is if settings.prompt_path was genuinely consulted to load THIS prompt.
_SENTINEL_PROMPT_LINE = "SENTINEL_PLUMBING_MARKER: this exact line proves prompt_path was consulted."


def _sentinel_leaky():
    # Same skeleton as test_build_report_gates_a_prompt_leak, but the notes carry
    # the sentinel prompt line verbatim and NAME NO compound schema fields, so the
    # schema-token path (>=3 distinct compound tokens) cannot fire — only the
    # prompt-line-signature path can.
    return {
        "schema_version": "v1", "alert_summary": "x", "severity": "low",
        "severity_rationale": "x", "mitre_techniques": [], "iocs": {},
        "iocs_enriched": [], "recommended_actions": [{"description": "x", "priority": "low"}],
        "investigation_notes": "Analyst narration follows.\n" + _SENTINEL_PROMPT_LINE,
    }


def test_prompt_path_is_actually_consulted(tmp_path):
    # DISCRIMINATING: proves settings.prompt_path drives the verifier's leak
    # signature. A broken plumbing (wrong field / unconditional None) would fall
    # back to the real deployed prompt, whose lines don't match the sentinel, and
    # with <3 schema tokens the gate would PASS — so this test FAILs iff the
    # explicit prompt_path is honoured.
    prompt_json = tmp_path / "wf.json"
    prompt_json.write_text(json.dumps({"nodes": [{
        "type": "@n8n/n8n-nodes-langchain.anthropic",
        "parameters": {"options": {"system": "You are a SOC analyst.\n" + _SENTINEL_PROMPT_LINE}},
    }]}), encoding="utf-8")

    settings = Settings(runs_path=str(tmp_path / "runs.jsonl"), prompt_path=str(prompt_json))
    rec = build_report(_sentinel_leaky(), retrieved=None, enrichment_results=None,
                       run_meta={}, settings=settings)
    assert rec["verification_passed"] is False
    names = {c["name"]: c["status"] for c in rec["check_results"]}
    assert names.get("notes_no_config_leak") == "failed"

    # Negative control: same sentinel notes with the DEFAULT (real deployed)
    # prompt -> the sentinel line matches nothing, <3 schema tokens -> gate PASSES.
    # Proves the temp prompt (not the default) drove the FAIL above.
    default = Settings(runs_path=str(tmp_path / "runs2.jsonl"))
    rec2 = build_report(_sentinel_leaky(), retrieved=None, enrichment_results=None,
                        run_meta={}, settings=default)
    names2 = {c["name"]: c["status"] for c in rec2["check_results"]}
    assert names2.get("notes_no_config_leak") == "passed"
