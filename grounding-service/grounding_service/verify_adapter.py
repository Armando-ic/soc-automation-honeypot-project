"""Adapter: run the 0C triage-verifier, append a run-log line, return JSON."""
from __future__ import annotations

from triage_verifier.judge import ClaudeJudge, StubJudge
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
) -> dict:
    judge = ClaudeJudge(client, model=settings.model) if client is not None else StubJudge()
    verifier = TriageVerifier.from_paths(
        settings.schema_path, settings.attack_ref_path, judge=judge
    )
    report = verifier.verify(
        result, retrieved=retrieved, enrichment_results=enrichment_results
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
