"""Dev-time faithfulness check: does the owned matcher agree with Zircolite on
every event in the frozen corpus? Run once when the matcher or corpus changes.
Not part of the pytest suite (Zircolite is a heavy external dependency).

Usage:
  1) clone https://github.com/wagga40/Zircolite and, in a SCRATCH venv (NOT the
     package venv), install its deps: pip install -r requirements.txt
  2) detection-authoring/.venv/Scripts/python scripts/crosscheck_zircolite.py \
       --zircolite /path/to/Zircolite/zircolite.py \
       --python /path/to/scratch-venv/Scripts/python
It writes each corpus event to NDJSON, runs Zircolite with each reference rule
as a single-rule ruleset, and asserts the detected/not-detected verdict equals
matcher.matches() for that (rule, event) pair.
"""
from __future__ import annotations

import argparse
import json
import os
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


def _zircolite_detects(python_exe: str, zircolite: str, rule_yaml: str, event: dict) -> bool:
    with tempfile.TemporaryDirectory() as d:
        dpath = Path(d)
        (dpath / "events.ndjson").write_text(json.dumps(event) + "\n", encoding="utf-8")
        (dpath / "rule.yml").write_text(rule_yaml, encoding="utf-8")
        out = dpath / "out.json"
        # Run zircolite.py with the SCRATCH venv's interpreter (which has
        # Zircolite's deps), not our own package venv. --json-input tells
        # Zircolite the --events file is NDJSON (older builds called this
        # --jsononly).
        # cwd = Zircolite's repo root so it finds its config/ (config.yaml +
        # fieldMappings.yaml) which it resolves relative to the working dir;
        # PYTHONIOENCODING keeps its rich logging from choking on a cp1252 console.
        subprocess.run(
            [python_exe, zircolite, "--events", str(dpath / "events.ndjson"),
             "--ruleset", str(dpath / "rule.yml"), "--json-input",
             "--outfile", str(out)],
            check=True, capture_output=True,
            cwd=str(Path(zircolite).resolve().parent),
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        results = json.loads(out.read_text(encoding="utf-8")) if out.exists() else []
        return bool(results)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zircolite", required=True, help="path to zircolite.py")
    ap.add_argument("--python", default=sys.executable,
                    help="interpreter that has Zircolite's deps (its scratch venv); "
                         "defaults to the current interpreter")
    args = ap.parse_args()

    disagreements = 0
    for tid, rule_yaml in REFERENCE_RULES.items():
        detection = yaml.safe_load(rule_yaml)["detection"]
        events = load_positives(tid) + load_benign()
        for ev in events:
            mine = matches(detection, ev)
            theirs = _zircolite_detects(args.python, args.zircolite, rule_yaml, ev)
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
