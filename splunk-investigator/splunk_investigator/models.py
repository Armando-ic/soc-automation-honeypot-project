from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class ParamSpec:
    name: str
    type: str                # "ip" | "host" | "user" | "window"


@dataclass(frozen=True)
class QuerySpec:
    name: str
    description: str
    params: tuple[ParamSpec, ...]
    spl_template: str
    result_cap: int
    time_bounded: bool
    derives: tuple[str, ...]   # names of QuerySpecs this one can pivot into


@dataclass(frozen=True)
class QueryResult:
    query_name: str
    params: dict
    outcome: str              # "ok" | "error" | "capped_incomplete"
    rows: tuple[dict, ...]
    row_count: int


@dataclass(frozen=True)
class ScopeClaim:
    type: str                 # a claim type from the v1 claim set
    fields: dict               # typed values incl. entity fields and counts


@dataclass(frozen=True)
class ScopeEvidence:
    claims: tuple[ScopeClaim, ...]
    queries_run: tuple[dict, ...]

    @classmethod
    def empty(cls) -> "ScopeEvidence":
        return cls(claims=(), queries_run=())


@dataclass(frozen=True)
class InvestigationResult:
    investigated: bool
    scope_evidence: ScopeEvidence
    transcript: tuple[dict, ...]
    flags: tuple[str, ...]
    advisory_reasoning: str

    @classmethod
    def empty(cls, flags: tuple[str, ...] = ()) -> "InvestigationResult":
        return cls(
            investigated=False,
            scope_evidence=ScopeEvidence.empty(),
            transcript=(),
            flags=flags,
            advisory_reasoning="",
        )
