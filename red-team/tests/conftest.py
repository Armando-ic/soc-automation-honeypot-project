import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent          # red-team/
REPO = ROOT.parent                                      # repo root
SNAP = ROOT / "snapshots"
WORKFLOW_JSON = REPO / "JSON" / "honeypot-triage.json"


def load_snapshot(name: str) -> dict:
    return json.loads((SNAP / f"{name}.json").read_text(encoding="utf-8"))
