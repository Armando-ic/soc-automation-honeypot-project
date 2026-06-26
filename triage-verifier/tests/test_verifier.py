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
