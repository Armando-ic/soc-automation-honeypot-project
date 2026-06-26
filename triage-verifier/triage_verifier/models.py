"""Frozen result/report data structures (ported from SOP-RAG)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CheckStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    NEEDS_HUMAN = "needs_human"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str = ""
    offending: tuple[str, ...] = ()


_BLOCKING = {CheckStatus.FAILED}
_NON_GATING = {CheckStatus.NEEDS_HUMAN, CheckStatus.NOT_APPLICABLE}


@dataclass(frozen=True)
class TriageVerificationReport:
    results: tuple[CheckResult, ...]
    reground_events: tuple[dict, ...] = ()
    repair_events: tuple[dict, ...] = ()
    provenance: tuple[dict, ...] = ()

    @property
    def passed(self) -> bool:
        return all(r.status is CheckStatus.PASSED for r in self.results if r.status not in _NON_GATING)
