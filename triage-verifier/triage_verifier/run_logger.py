"""Append-only JSONL run-log + a small aggregate printer (honeypot spec §6.2)."""
from __future__ import annotations

import json
from pathlib import Path

from triage_verifier.models import TriageVerificationReport


def build_run_record(*, run_id: str, timestamp: str, model: str, schema_version: str,
                     tokens_in: int, tokens_out: int, latency_ms: int,
                     report: TriageVerificationReport) -> dict:
    return {
        "run_id": run_id,
        "timestamp": timestamp,
        "model": model,
        "schema_version": schema_version,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "latency_ms": latency_ms,
        "verification_passed": report.passed,
        "check_results": [
            {"name": r.name, "status": r.status.value, "detail": r.detail, "offending": list(r.offending)}
            for r in report.results
        ],
        "provenance": list(report.provenance),
        "reground_events": list(report.reground_events),
        "repair_events": list(report.repair_events),
    }


class RunLogger:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def append(self, record: dict) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


def aggregate(path: str | Path) -> dict:
    records = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    n = len(records)
    if n == 0:
        return {"runs": 0, "pass_rate": 0.0, "avg_latency_ms": 0, "total_tokens": 0}
    passed = sum(1 for r in records if r["verification_passed"])
    return {
        "runs": n,
        "pass_rate": passed / n,
        "avg_latency_ms": sum(r["latency_ms"] for r in records) // n,
        "total_tokens": sum(r["tokens_in"] + r["tokens_out"] for r in records),
    }
