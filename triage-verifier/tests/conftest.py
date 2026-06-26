import json
from pathlib import Path

import pytest

from triage_verifier.attack_reference import AttackReference
from triage_verifier.verifier import TriageVerifier

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "submit_triage_result.json"
DATA = ROOT / "data" / "attack_reference.json"
FIX = ROOT / "golden" / "fixtures"


@pytest.fixture
def verifier():
    return TriageVerifier.from_paths(SCHEMA, DATA)


def load_fixture(category: str, name: str) -> dict:
    return json.loads((FIX / category / f"{name}.json").read_text(encoding="utf-8"))


def status_of(report, check_name):
    return next((r.status for r in report.results if r.name == check_name), None)
