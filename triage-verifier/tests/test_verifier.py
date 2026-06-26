from triage_verifier.models import CheckStatus
from tests.conftest import load_fixture, status_of


def test_positive_passes_schema(verifier):
    fx = load_fixture("positive", "rdp_bruteforce")
    report = verifier.verify(fx["result"])
    assert status_of(report, "schema_valid") == CheckStatus.PASSED


def test_bad_enum_fails_schema(verifier):
    fx = load_fixture("negative", "bad_enum")
    report = verifier.verify(fx["result"])
    assert status_of(report, "schema_valid") == CheckStatus.FAILED
    assert report.passed is False


def test_ungrounded_ioc_fails(verifier):
    fx = load_fixture("negative", "ungrounded_ioc")
    report = verifier.verify(fx["result"])
    assert status_of(report, "iocs_enriched_grounded") == CheckStatus.FAILED


def test_ioc_type_mismatch_fails(verifier):
    fx = load_fixture("negative", "ioc_type_mismatch")
    report = verifier.verify(fx["result"])
    assert status_of(report, "ioc_type_consistent") == CheckStatus.FAILED


def test_positive_passes_ioc_checks(verifier):
    fx = load_fixture("positive", "rdp_bruteforce")
    report = verifier.verify(fx["result"])
    assert status_of(report, "iocs_enriched_grounded") == CheckStatus.PASSED
    assert status_of(report, "ioc_type_consistent") == CheckStatus.PASSED


import pytest


@pytest.mark.parametrize("name,check", [
    ("invented_technique", "mitre_id_exists"),
    ("wrong_name", "mitre_name_match"),
    ("wrong_tactic", "mitre_tactic_valid"),
])
def test_mitre_negative_fixtures(verifier, name, check):
    report = verifier.verify(load_fixture("negative", name)["result"])
    assert status_of(report, check) == CheckStatus.FAILED


def test_positive_passes_mitre_checks(verifier):
    report = verifier.verify(load_fixture("positive", "rdp_bruteforce")["result"])
    for check in ("mitre_id_exists", "mitre_name_match", "mitre_tactic_valid"):
        assert status_of(report, check) == CheckStatus.PASSED


def test_unsupported_critical_fails(verifier):
    report = verifier.verify(load_fixture("negative", "unsupported_critical")["result"])
    assert status_of(report, "severity_supported") == CheckStatus.FAILED


def test_unsourced_verdict_fails(verifier):
    report = verifier.verify(load_fixture("negative", "unsourced_verdict")["result"])
    assert status_of(report, "verdict_sourced") == CheckStatus.FAILED


def test_positive_passes_all_eight_and_has_provenance(verifier):
    report = verifier.verify(load_fixture("positive", "rdp_bruteforce")["result"])
    deterministic = [r for r in report.results if r.status != CheckStatus.NOT_APPLICABLE]
    assert all(r.status == CheckStatus.PASSED for r in deterministic)
    assert any(p["kind"] == "technique" for p in report.provenance)
    assert any(p["kind"] == "ioc" for p in report.provenance)
