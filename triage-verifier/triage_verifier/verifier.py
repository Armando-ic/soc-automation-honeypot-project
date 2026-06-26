"""Pure credibility-gate verifier over submit_triage_result output."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from triage_verifier.attack_reference import AttackReference
from triage_verifier.models import CheckResult, CheckStatus, TriageVerificationReport
from triage_verifier.normalizer import normalize_triage_result


class TriageVerifier:
    def __init__(self, schema: dict, attack_ref: AttackReference, judge=None) -> None:
        self._schema = schema
        self._ref = attack_ref
        self._judge = judge
        self._validator = jsonschema.Draft7Validator(schema)

    @classmethod
    def from_paths(cls, schema_path, attack_ref_path, judge=None) -> "TriageVerifier":
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        return cls(schema, AttackReference.load(attack_ref_path), judge)

    def verify(self, result: dict, *, retrieved=None, enrichment_results=None) -> TriageVerificationReport:
        norm, repair_events = normalize_triage_result(result)
        results: list[CheckResult] = [self._check_schema_valid(norm)]
        return TriageVerificationReport(
            results=tuple(results),
            repair_events=tuple(repair_events),
        )

    # --- check 1 -------------------------------------------------------------
    def _check_schema_valid(self, norm: dict) -> CheckResult:
        errors = sorted(self._validator.iter_errors(norm), key=lambda e: e.path)
        if not errors:
            return CheckResult("schema_valid", CheckStatus.PASSED)
        offending = tuple("/".join(str(p) for p in e.path) or "<root>" for e in errors)
        return CheckResult("schema_valid", CheckStatus.FAILED, "schema violations", offending)
