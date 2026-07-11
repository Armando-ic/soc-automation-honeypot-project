# splunk-investigator/tests/test_scaffold.py
from splunk_investigator.models import ScopeEvidence, InvestigationResult
from splunk_investigator.config import load_config


def test_empty_investigation_result_is_well_typed_object():
    r = InvestigationResult.empty(flags=("no_pivot",))
    assert r.investigated is False
    assert isinstance(r.scope_evidence, ScopeEvidence)
    assert r.scope_evidence.claims == ()
    assert r.scope_evidence.queries_run == ()
    assert r.flags == ("no_pivot",)


def test_config_defaults():
    cfg = load_config()
    assert cfg.model == "claude-opus-4-8"
    assert cfg.max_queries < 5          # below catalog size, forces prioritization
    assert cfg.max_turns >= cfg.max_queries
    assert cfg.enabled is True
    assert cfg.live_indexes == ("honeypot",)   # mydfir-project NOT live
