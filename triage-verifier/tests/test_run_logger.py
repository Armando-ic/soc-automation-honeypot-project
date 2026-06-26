from triage_verifier.models import CheckResult, CheckStatus, TriageVerificationReport
from triage_verifier.run_logger import RunLogger, aggregate, build_run_record


def _report(passed: bool):
    status = CheckStatus.PASSED if passed else CheckStatus.FAILED
    return TriageVerificationReport(results=(CheckResult("schema_valid", status),))


def test_build_record_flattens_report():
    rec = build_run_record(run_id="r1", timestamp="2026-06-26T00:00:00Z", model="claude-opus-4-8",
                           schema_version="v1", tokens_in=10, tokens_out=20, latency_ms=123,
                           report=_report(True))
    assert rec["verification_passed"] is True
    assert rec["check_results"][0]["name"] == "schema_valid"
    assert rec["tokens_out"] == 20


def test_logger_appends_and_aggregates(tmp_path):
    path = tmp_path / "runs.jsonl"
    logger = RunLogger(path)
    logger.append(build_run_record(run_id="r1", timestamp="t", model="m", schema_version="v1",
                                   tokens_in=10, tokens_out=20, latency_ms=100, report=_report(True)))
    logger.append(build_run_record(run_id="r2", timestamp="t", model="m", schema_version="v1",
                                   tokens_in=5, tokens_out=5, latency_ms=200, report=_report(False)))
    agg = aggregate(path)
    assert agg["runs"] == 2
    assert agg["pass_rate"] == 0.5
    assert agg["avg_latency_ms"] == 150
    assert agg["total_tokens"] == 40
