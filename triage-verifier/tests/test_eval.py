from pathlib import Path

from triage_verifier.eval_runner import run_eval

ROOT = Path(__file__).resolve().parent.parent


def test_all_golden_fixtures_match_expected():
    out = run_eval(ROOT / "golden" / "fixtures", ROOT / "schema" / "submit_triage_result.json",
                   ROOT / "data" / "attack_reference.json")
    assert out["mismatches"] == []
    assert out["total"] >= 13
