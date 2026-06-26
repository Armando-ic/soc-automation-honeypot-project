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
