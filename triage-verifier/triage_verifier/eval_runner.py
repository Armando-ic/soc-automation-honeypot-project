"""Run the verifier over the golden fixtures and score against expected outcomes."""
from __future__ import annotations

import json
from pathlib import Path

from triage_verifier.judge import StubJudge
from triage_verifier.models import CheckStatus
from triage_verifier.verifier import TriageVerifier


def run_eval(fixtures_dir: str | Path, schema_path: str | Path, attack_ref_path: str | Path) -> dict:
    verifier = TriageVerifier.from_paths(schema_path, attack_ref_path, judge=StubJudge())
    mismatches: list[dict] = []
    total = 0
    for fx_path in sorted(Path(fixtures_dir).rglob("*.json")):
        fx = json.loads(fx_path.read_text(encoding="utf-8"))
        total += 1
        report = verifier.verify(fx["result"])
        exp = fx["expected"]
        failed = [r.name for r in report.results if r.status == CheckStatus.FAILED]
        ok = report.passed == exp["passed"]
        if exp["fails_check"] is not None:
            ok = ok and exp["fails_check"] in failed
        else:
            ok = ok and not failed
        if not ok:
            mismatches.append({"fixture": fx["name"], "expected": exp, "actual_failed": failed})
    return {"total": total, "matched": total - len(mismatches), "mismatches": mismatches}
