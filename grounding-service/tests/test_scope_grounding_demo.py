"""Task 17 deliverable #2 (offline component): the scope-grounding demo runs the
SAME /verify adapter (build_report) the live ablation uses, on two labeled-
SYNTHETIC fixtures, and proves each grounding channel flips pass->fail when
scope_evidence is removed. This regression-locks the demo's claimed flips
against any future verifier drift, so the portfolio artifact can never silently
start lying."""
from grounding_service.config import Settings
from grounding_service.scope_grounding_demo import build_scenarios, render_markdown, run_demo


def _by_name(tmp_path):
    results = run_demo(Settings(runs_path=str(tmp_path / "runs.jsonl")))
    return {r["name"]: r for r in results}


def test_two_scenarios_one_per_channel():
    scenarios = build_scenarios()
    checks = {s["check"] for s in scenarios}
    assert checks == {"scope_findings_grounded", "severity_supported"}


def test_scope_findings_grounded_channel_flips(tmp_path):
    # The honeypot-relevant channel: a model that copies grounded claims into
    # scope_findings is trusted WITH scope_evidence, but fails CLOSED without it.
    r = _by_name(tmp_path)["scope_findings_grounded_flip"]
    assert r["check"] == "scope_findings_grounded"
    assert r["with_scope"] == "passed"
    assert r["without_scope"] == "failed"


def test_severity_supported_channel_flips(tmp_path):
    # The post-exploit escalation channel (synthetic -- honeypot data can't
    # produce a successful auth): a high severity with no bad IOC and a non-hot
    # tactic is justified ONLY by grounded successful-auth evidence.
    r = _by_name(tmp_path)["severity_supported_backing"]
    assert r["check"] == "severity_supported"
    assert r["with_scope"] == "passed"
    assert r["without_scope"] == "failed"


def test_overall_verification_flips_on_both_scenarios(tmp_path):
    # The portfolio headline: removing scope_evidence drops the whole report
    # from pass to Needs-Human on BOTH scenarios.
    for r in _by_name(tmp_path).values():
        assert r["with_verification_passed"] is True
        assert r["without_verification_passed"] is False


def test_render_markdown_labels_synthetic_and_names_checks(tmp_path):
    md = render_markdown(run_demo(Settings(runs_path=str(tmp_path / "runs.jsonl"))))
    assert "SYNTHETIC" in md.upper()
    assert "scope_findings_grounded" in md
    assert "severity_supported" in md
