from pathlib import Path

from triage_verifier.attack_reference import AttackReference

DATA = Path(__file__).resolve().parent.parent / "data" / "attack_reference.json"


def ref():
    return AttackReference.load(DATA)


def test_id_exists():
    r = ref()
    assert r.id_exists("T1059.001") is True
    assert r.id_exists("T9999") is False


def test_name_for():
    assert ref().name_for("T1059.001") == "PowerShell"
    assert ref().name_for("T9999") is None


def test_tactics_for():
    assert "credential-access" in ref().tactics_for("T1003")
    assert ref().tactics_for("T9999") == ()
