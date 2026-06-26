"""Pure credibility-gate verifier over submit_triage_result output."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import jsonschema

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def _norm_name(s: str) -> str:
    return " ".join(s.split()).lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_hash(value: str) -> bool:
    return len(value) in (32, 40, 64) and bool(_HEX_RE.match(value))


def _is_domain(value: str) -> bool:
    return not _is_ip(value) and bool(_DOMAIN_RE.match(value))


_BUCKET_FOR_TYPE = {"ip": "ips", "domain": "domains", "file_hash": "file_hashes"}
_SHAPE_FOR_TYPE = {"ip": _is_ip, "domain": _is_domain, "file_hash": _is_hash}

from triage_verifier.attack_reference import AttackReference
from triage_verifier.constants import BAD_VERDICTS, HIGH_SEVERITY_TACTICS
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
        results: list[CheckResult] = [
            self._check_schema_valid(norm),
            self._check_iocs_enriched_grounded(norm),
            self._check_ioc_type_consistent(norm),
            self._check_mitre_id_exists(norm),
            self._check_mitre_name_match(norm),
            self._check_mitre_tactic_valid(norm),
            self._check_severity_supported(norm),
            self._check_verdict_sourced(norm),
        ]
        if self._judge is not None:
            results.append(self._judge.assess(norm, self._ref))
        results.append(self._check_mitre_in_retrieved(norm, retrieved))
        results.append(self._check_enrichment_grounded(norm, enrichment_results))
        return TriageVerificationReport(
            results=tuple(results),
            repair_events=tuple(repair_events),
            provenance=self._build_provenance(norm),
        )

    # --- check 1 -------------------------------------------------------------
    def _check_schema_valid(self, norm: dict) -> CheckResult:
        errors = sorted(self._validator.iter_errors(norm), key=lambda e: e.path)
        if not errors:
            return CheckResult("schema_valid", CheckStatus.PASSED)
        offending = tuple("/".join(str(p) for p in e.path) or "<root>" for e in errors)
        return CheckResult("schema_valid", CheckStatus.FAILED, "schema violations", offending)

    # --- check 2 -------------------------------------------------------------
    def _check_iocs_enriched_grounded(self, norm: dict) -> CheckResult:
        observed = {v for bucket in norm["iocs"].values() for v in bucket}
        offending = tuple(e["value"] for e in norm["iocs_enriched"]
                          if e.get("value") not in observed)
        if offending:
            return CheckResult("iocs_enriched_grounded", CheckStatus.FAILED,
                               "enriched IOC not in observed iocs", offending)
        return CheckResult("iocs_enriched_grounded", CheckStatus.PASSED)

    # --- check 3 -------------------------------------------------------------
    def _check_ioc_type_consistent(self, norm: dict) -> CheckResult:
        offending: list[str] = []
        for e in norm["iocs_enriched"]:
            value, ioc_type = e.get("value", ""), e.get("ioc_type", "")
            shape_ok = _SHAPE_FOR_TYPE.get(ioc_type, lambda _v: False)(value)
            bucket = _BUCKET_FOR_TYPE.get(ioc_type)
            in_right_bucket = bucket is None or value in norm["iocs"].get(bucket, [])
            if not shape_ok or not in_right_bucket:
                offending.append(value)
        if offending:
            return CheckResult("ioc_type_consistent", CheckStatus.FAILED,
                               "ioc_type mismatches value shape or bucket", tuple(offending))
        return CheckResult("ioc_type_consistent", CheckStatus.PASSED)

    # --- check 4 -------------------------------------------------------------
    def _check_mitre_id_exists(self, norm: dict) -> CheckResult:
        offending = tuple(t.get("id", "") for t in norm["mitre_techniques"]
                          if not self._ref.id_exists(t.get("id", "")))
        if offending:
            return CheckResult("mitre_id_exists", CheckStatus.FAILED,
                               "technique id not in ATT&CK reference", offending)
        return CheckResult("mitre_id_exists", CheckStatus.PASSED)

    # --- check 5 -------------------------------------------------------------
    def _check_mitre_name_match(self, norm: dict) -> CheckResult:
        offending: list[str] = []
        for t in norm["mitre_techniques"]:
            official = self._ref.name_for(t.get("id", ""))
            if official is not None and _norm_name(t.get("name", "")) != _norm_name(official):
                offending.append(t.get("id", ""))
        if offending:
            return CheckResult("mitre_name_match", CheckStatus.FAILED,
                               "technique name does not match ATT&CK", tuple(offending))
        return CheckResult("mitre_name_match", CheckStatus.PASSED)

    # --- check 6 -------------------------------------------------------------
    def _check_mitre_tactic_valid(self, norm: dict) -> CheckResult:
        offending: list[str] = []
        for t in norm["mitre_techniques"]:
            tid = t.get("id", "")
            tactics = self._ref.tactics_for(tid)
            if tactics and _norm_name(t.get("tactic", "")).replace(" ", "-") not in tactics:
                offending.append(tid)
        if offending:
            return CheckResult("mitre_tactic_valid", CheckStatus.FAILED,
                               "tactic not valid for technique", tuple(offending))
        return CheckResult("mitre_tactic_valid", CheckStatus.PASSED)

    # --- check 7 -------------------------------------------------------------
    def _check_severity_supported(self, norm: dict) -> CheckResult:
        severity = norm.get("severity")
        if severity not in ("high", "critical"):
            return CheckResult("severity_supported", CheckStatus.PASSED)
        has_bad_ioc = any(e.get("verdict") in BAD_VERDICTS for e in norm["iocs_enriched"])
        has_hot_tactic = any(
            set(self._ref.tactics_for(t.get("id", ""))) & HIGH_SEVERITY_TACTICS
            for t in norm["mitre_techniques"]
        )
        if has_bad_ioc or has_hot_tactic:
            return CheckResult("severity_supported", CheckStatus.PASSED)
        return CheckResult("severity_supported", CheckStatus.FAILED,
                           "high/critical without malicious IOC or high-severity tactic",
                           (f"severity:{severity}",))

    # --- check 8 -------------------------------------------------------------
    def _check_verdict_sourced(self, norm: dict) -> CheckResult:
        offending = tuple(e.get("value", "") for e in norm["iocs_enriched"]
                          if e.get("verdict") in BAD_VERDICTS and not (e.get("source") or "").strip())
        if offending:
            return CheckResult("verdict_sourced", CheckStatus.FAILED,
                               "malicious/suspicious verdict without a source", offending)
        return CheckResult("verdict_sourced", CheckStatus.PASSED)

    # --- provenance ----------------------------------------------------------
    def _build_provenance(self, norm: dict) -> tuple[dict, ...]:
        prov: list[dict] = []
        for t in norm["mitre_techniques"]:
            tid = t.get("id", "")
            prov.append({"item": tid, "kind": "technique",
                         "grounded_in": "attack_reference" if self._ref.id_exists(tid) else "absent",
                         "note": self._ref.name_for(tid) or ""})
        observed = {v for bucket in norm["iocs"].values() for v in bucket}
        for e in norm["iocs_enriched"]:
            val = e.get("value", "")
            prov.append({"item": val, "kind": "ioc",
                         "grounded_in": "observed_iocs" if val in observed else "absent",
                         "note": e.get("verdict", "")})
        return tuple(prov)

    # --- deferred check: mitre_in_retrieved (0D supplies `retrieved`) ---------
    def _check_mitre_in_retrieved(self, norm: dict, retrieved) -> CheckResult:
        if retrieved is None:
            return CheckResult("mitre_in_retrieved", CheckStatus.NOT_APPLICABLE,
                               "no Qdrant retrieval context (wired in Plan 0D)")
        retrieved_set = set(retrieved)
        offending = tuple(t.get("id", "") for t in norm["mitre_techniques"]
                          if t.get("id", "") not in retrieved_set)
        if offending:
            return CheckResult("mitre_in_retrieved", CheckStatus.FAILED,
                               "cited technique not in retrieved set", offending)
        return CheckResult("mitre_in_retrieved", CheckStatus.PASSED)

    # --- deferred check: enrichment_grounded (0D supplies live results) -------
    def _check_enrichment_grounded(self, norm: dict, enrichment_results) -> CheckResult:
        if enrichment_results is None:
            return CheckResult("enrichment_grounded", CheckStatus.NOT_APPLICABLE,
                               "no live enrichment context (wired in Plan 0D)")
        offending: list[str] = []
        for e in norm["iocs_enriched"]:
            if e.get("verdict") in BAD_VERDICTS:
                actual = enrichment_results.get(e.get("value", ""))
                if actual not in BAD_VERDICTS:
                    offending.append(e.get("value", ""))
        if offending:
            return CheckResult("enrichment_grounded", CheckStatus.FAILED,
                               "verdict not grounded in live enrichment", tuple(offending))
        return CheckResult("enrichment_grounded", CheckStatus.PASSED)
