"""Adapter: run the 0C triage-verifier, append a run-log line, return JSON."""
from __future__ import annotations

from triage_verifier.judge import ClaudeJudge, StubJudge
from triage_verifier.models import CheckResult, CheckStatus, TriageVerificationReport
from triage_verifier.run_logger import RunLogger, build_run_record
from triage_verifier.verifier import TriageVerifier

from grounding_service.config import Settings


def build_report(
    result: dict,
    *,
    retrieved: list[str] | None,
    enrichment_results: dict[str, str] | None,
    run_meta: dict,
    settings: Settings,
    client: object | None = None,
    scope_evidence: dict | None = None,
) -> dict:
    judge = ClaudeJudge(client, model=settings.model) if client is not None else StubJudge()
    try:
        verifier = TriageVerifier.from_paths(
            settings.schema_path, settings.attack_ref_path, judge=judge,
            prompt_path=settings.prompt_path,
        )
        report = verifier.verify(
            result, retrieved=retrieved, enrichment_results=enrichment_results,
            scope_evidence=scope_evidence,
        )
    except Exception as exc:  # never drop an event: log + gate false, never surface a 500
        report = TriageVerificationReport(
            results=(
                CheckResult("verifier_error", CheckStatus.FAILED, f"verifier raised: {exc}"),
            ),
        )
    record = build_run_record(
        run_id=run_meta.get("run_id", ""),
        timestamp=run_meta.get("timestamp", ""),
        model=settings.model,
        schema_version=result.get("schema_version", ""),
        tokens_in=int(run_meta.get("tokens_in", 0)),
        tokens_out=int(run_meta.get("tokens_out", 0)),
        latency_ms=int(run_meta.get("latency_ms", 0)),
        report=report,
    )
    RunLogger(settings.runs_path).append(record)
    return record
