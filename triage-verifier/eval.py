"""Eval gate: verify every golden fixture matches its expected outcome.

Run from the package root:  python eval.py
Exits nonzero on any mismatch (use in CI / before shipping a verifier change).
"""
from __future__ import annotations

import sys
from pathlib import Path

from triage_verifier.eval_runner import run_eval

ROOT = Path(__file__).resolve().parent


def main() -> int:
    out = run_eval(ROOT / "golden" / "fixtures", ROOT / "schema" / "submit_triage_result.json",
                   ROOT / "data" / "attack_reference.json")
    print(f"fixtures: {out['matched']}/{out['total']} matched expected")
    for m in out["mismatches"]:
        print(f"  MISMATCH {m['fixture']}: expected {m['expected']} got failed={m['actual_failed']}")
    return 0 if not out["mismatches"] else 1


if __name__ == "__main__":
    sys.exit(main())
