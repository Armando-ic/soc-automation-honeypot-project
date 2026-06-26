from triage_verifier.constants import HIGH_SEVERITY_TACTICS, MODEL
from triage_verifier.models import CheckResult, CheckStatus, TriageVerificationReport


def _r(name, status):
    return CheckResult(name=name, status=status)


def test_passed_true_when_all_pass():
    rep = TriageVerificationReport(results=(_r("a", CheckStatus.PASSED), _r("b", CheckStatus.PASSED)))
    assert rep.passed is True


def test_passed_false_on_any_failure():
    rep = TriageVerificationReport(results=(_r("a", CheckStatus.PASSED), _r("b", CheckStatus.FAILED)))
    assert rep.passed is False


def test_needs_human_and_not_applicable_do_not_block():
    rep = TriageVerificationReport(
        results=(_r("a", CheckStatus.PASSED), _r("judge", CheckStatus.NEEDS_HUMAN),
                 _r("deferred", CheckStatus.NOT_APPLICABLE)))
    assert rep.passed is True


def test_constants_present():
    assert MODEL == "claude-opus-4-8"
    assert "credential-access" in HIGH_SEVERITY_TACTICS
