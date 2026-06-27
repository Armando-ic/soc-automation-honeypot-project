import triage_verifier  # the 0C package must be importable in this venv
from grounding_service.config import Settings, load_settings


def test_triage_verifier_importable():
    assert triage_verifier.__doc__


def test_settings_defaults():
    s = load_settings()
    assert isinstance(s, Settings)
    assert s.collection == "attack_techniques"
    assert s.model == "claude-opus-4-8"
    assert s.top_k_default == 6
