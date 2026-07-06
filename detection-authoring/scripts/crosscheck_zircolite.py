"""Dev-time faithfulness check: does the owned matcher agree with Zircolite on
every event in the frozen corpus? Run once when the matcher or corpus changes.
Not part of the pytest suite (Zircolite is a heavy external dependency).

Usage:
  1) pip install zircolite  (in a scratch venv, NOT the package venv)
  2) detection-authoring/.venv/Scripts/python scripts/crosscheck_zircolite.py \
       --zircolite /path/to/zircolite.py
It writes each corpus event to NDJSON, runs Zircolite with each reference rule
as a single-rule ruleset, and asserts the detected/not-detected verdict equals
matcher.matches() for that (rule, event) pair.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from detection_authoring.corpus import load_benign, load_positives
from detection_authoring.matcher import matches

REFERENCE_RULES = {
    "T1059.001": """
title: PS Encoded ref
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|re: '(?i)\\s-e(nc(odedcommand)?)?\\s'
  condition: selection
""",
}


def _zircolite_detects(zircolite: str, rule_yaml: str, event: dict) -> bool:
    with tempfile.TemporaryDirectory() as d:
        dpath = Path(d)
        (dpath / "events.ndjson").write_text(json.dumps(event) + "\n", encoding="utf-8")
        (dpath / "rule.yml").write_text(rule_yaml, encoding="utf-8")
        out = dpath / "out.json"
        subprocess.run(
            [sys.executable, zircolite, "--events", str(dpath / "events.ndjson"),
             "--ruleset", str(dpath / "rule.yml"), "--jsononly",
             "--outfile", str(out)],
            check=True, capture_output=True,
        )
        results = json.loads(out.read_text(encoding="utf-8")) if out.exists() else []
        return bool(results)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zircolite", required=True, help="path to zircolite.py")
    args = ap.parse_args()

    disagreements = 0
    for tid, rule_yaml in REFERENCE_RULES.items():
        detection = yaml.safe_load(rule_yaml)["detection"]
        events = load_positives(tid) + load_benign()
        for ev in events:
            mine = matches(detection, ev)
            theirs = _zircolite_detects(args.zircolite, rule_yaml, ev)
            if mine != theirs:
                disagreements += 1
                print(f"DISAGREE {tid}: matcher={mine} zircolite={theirs} event={ev.get('CommandLine')}")
    if disagreements:
        print(f"{disagreements} disagreement(s): the owned matcher is NOT faithful. Fix before shipping.")
        return 1
    print("Owned matcher agrees with Zircolite on the whole corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
