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


def _canon(value: object) -> object:
    """Canonicalize an IP-shaped string so differently-formatted-but-equal
    addresses compare equal; anything else (including non-IP strings, ints,
    None) passes through unchanged."""
    if isinstance(value, str):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    return value


def _findings_equal(a: dict, b: dict) -> bool:
    """Field-for-field equality of two flat scope_finding/claim dicts, after
    canonicalizing IP-valued fields. Key sets must match exactly (so a
    finding can't drop or add fields to dodge comparison); None == None.

    scope_findings is fully model-controlled and NOT schema-validated, so a
    non-dict entry (e.g. a bare string/int in the list) can reach here. A
    non-dict on either side simply never matches (fail CLOSED downstream in
    scope_findings_grounded -> FAILED, never a crash)."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if set(a.keys()) != set(b.keys()):
        return False
    return all(_canon(a[k]) == _canon(b[k]) for k in a)


# Scope-outcome assertions a triage's investigation_notes might make. Each is
# matched per-sentence and skipped if a negation cue appears in the same
# sentence (e.g. "no successful logon observed yet" must NOT be treated as
# a positive claim of a successful logon).
_SCOPE_ASSERTION_RES = {
    "auth_outcome": re.compile(r"successful (logon|auth)", re.IGNORECASE),
    "lateral_movement": re.compile(r"lateral movement", re.IGNORECASE),
    "exfil": re.compile(r"exfil", re.IGNORECASE),
    "post_exploit": re.compile(r"post-exploit", re.IGNORECASE),
}
_NEGATION_RE = re.compile(
    r"\b(no|not|never|without|didn't|did not|hasn't|has not|isn't|wasn't|absent|lacks?|none)\b",
    re.IGNORECASE,
)
_SENTENCE_SPLIT_RE = re.compile(r"[.;!?\n]+")

from triage_verifier.attack_reference import AttackReference
from triage_verifier.constants import BAD_VERDICTS, HIGH_SEVERITY_TACTICS
from triage_verifier.models import CheckResult, CheckStatus, TriageVerificationReport
from triage_verifier.normalizer import normalize_triage_result

_MIN_PROMPT_LINE = 24  # chars; verbatim prompt lines shorter than this are too generic to gate on
_BAND_LINE_RE = re.compile(r"^-?\s*(low|medium|high|critical)\s*:", re.IGNORECASE)


def _resolve_deployed_prompt() -> str | None:
    """Best-effort load of the deployed system prompt (options.system) from the
    canonical workflow JSON at <repo>/JSON/honeypot-triage.json. Returns None if
    the file is absent/unreadable so the verifier stays usable in isolation."""
    try:
        repo_root = Path(__file__).resolve().parents[2]
        wf = json.loads((repo_root / "JSON" / "honeypot-triage.json").read_text(encoding="utf-8"))
        for node in wf.get("nodes", []):
            if node.get("type") == "@n8n/n8n-nodes-langchain.anthropic":
                return node["parameters"]["options"]["system"]
    except Exception:
        return None
    return None


def _build_leak_signature(prompt: str | None, schema: dict) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(prompt_lines, distinctive_fields). Prompt lines >=24 chars (EXCLUDING
    generic severity-band definition lines) match as substrings; distinctive
    compound (underscore) schema field names match as whole tokens. Close to
    the frozen scorer's derivation but deliberately STRICTER (band lines
    excluded here; the >=3-token bar is applied in the check) to avoid false
    gates on non-C1 trials. The distinctive-field SET matches the scorer's;
    a test pins it (test_distinctive_fields_are_the_compound_schema_names)."""
    prompt_lines: set[str] = set()
    if prompt:
        for line in prompt.splitlines():
            line = line.strip()
            if len(line) >= _MIN_PROMPT_LINE and not _BAND_LINE_RE.match(line):
                prompt_lines.add(line)
    distinctive: set[str] = set()

    def _walk(node: object) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if key == "properties" and isinstance(val, dict):
                    for field_name in val:
                        if "_" in field_name:
                            distinctive.add(field_name)
                _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(schema)
    return tuple(prompt_lines), tuple(distinctive)


class TriageVerifier:
    def __init__(self, schema: dict, attack_ref: AttackReference, judge=None,
                 leak_prompt: str | None = None) -> None:
        self._schema = schema
        self._ref = attack_ref
        self._judge = judge
        self._validator = jsonschema.Draft7Validator(schema)
        self._leak_signature = _build_leak_signature(leak_prompt, schema)

    @classmethod
    def from_paths(cls, schema_path, attack_ref_path, judge=None,
                   prompt_path=None) -> "TriageVerifier":
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        if prompt_path is not None:
            wf = json.loads(Path(prompt_path).read_text(encoding="utf-8"))
            leak_prompt = next(
                (n["parameters"]["options"]["system"] for n in wf.get("nodes", [])
                 if n.get("type") == "@n8n/n8n-nodes-langchain.anthropic"),
                None,
            )
        else:
            leak_prompt = _resolve_deployed_prompt()
        return cls(schema, AttackReference.load(attack_ref_path), judge, leak_prompt=leak_prompt)

    def verify(self, result: dict, *, retrieved=None, enrichment_results=None,
               scope_evidence=None) -> TriageVerificationReport:
        norm, repair_events = normalize_triage_result(result)
        results: list[CheckResult] = [
            self._check_schema_valid(norm),
            self._check_iocs_enriched_grounded(norm),
            self._check_ioc_type_consistent(norm),
            self._check_mitre_id_exists(norm),
            self._check_mitre_name_match(norm),
            self._check_mitre_tactic_valid(norm),
            self._check_severity_supported(norm, scope_evidence),
            self._check_verdict_sourced(norm),
            self._check_notes_no_config_leak(norm),
            self._check_scope_findings_grounded(norm, scope_evidence),
            self._check_scope_notes_honesty(norm, scope_evidence),
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
        observed = {v for vals in norm["iocs"].values() for v in vals}
        offending: list[str] = []
        for e in norm["iocs_enriched"]:
            value, ioc_type = e.get("value", ""), e.get("ioc_type", "")
            shape_ok = _SHAPE_FOR_TYPE.get(ioc_type, lambda _v: False)(value)
            bucket = _BUCKET_FOR_TYPE.get(ioc_type)
            in_right_bucket = (
                bucket is None
                or value not in observed
                or value in norm["iocs"].get(bucket, [])
            )
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
    def _check_severity_supported(self, norm: dict, scope_evidence=None) -> CheckResult:
        severity = norm.get("severity")
        if severity not in ("high", "critical"):
            return CheckResult("severity_supported", CheckStatus.PASSED)
        has_bad_ioc = any(e.get("verdict") in BAD_VERDICTS for e in norm["iocs_enriched"])
        has_hot_tactic = any(
            set(self._ref.tactics_for(t.get("id", ""))) & HIGH_SEVERITY_TACTICS
            for t in norm["mitre_techniques"]
        )
        valid_scope_backing = self._valid_scope_backing(norm, severity, scope_evidence)
        if has_bad_ioc or has_hot_tactic or valid_scope_backing:
            return CheckResult("severity_supported", CheckStatus.PASSED)
        return CheckResult("severity_supported", CheckStatus.FAILED,
                           "high/critical without malicious IOC, high-severity tactic, "
                           "or grounded scope backing",
                           (f"severity:{severity}",))

    def _valid_scope_backing(self, norm: dict, severity: str, scope_evidence) -> bool:
        """Whether scope_evidence (the GROUND TRUTH, out of model control -- never
        norm['scope_findings']) backs a high/critical severity for THIS alert's
        own src_ip/host. Returns False (never raises) on any missing field, which
        also makes this reduce to exactly the pre-Task-10 behavior when
        scope_evidence is None (the backward-compat requirement)."""
        if not scope_evidence:
            return False
        claims = scope_evidence.get("claims") or []
        src_ip = norm.get("src_ip")
        if not src_ip:
            return False
        canon_src_ip = _canon(src_ip)

        def _positive_int(value: object) -> bool:
            return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0

        auth_ok = any(
            c.get("type") == "auth_outcome"
            and _canon(c.get("ip")) == canon_src_ip
            and _positive_int(c.get("success_count"))
            for c in claims
        )
        if severity == "high":
            return auth_ok
        if severity == "critical":
            host = norm.get("host")
            if not host:
                return False
            process_ok = any(
                c.get("type") in ("encoded_powershell", "process_exec_by_user_in_window")
                and c.get("host") == host
                and _positive_int(c.get("count"))
                for c in claims
            )
            return auth_ok and process_ok
        return False

    # --- check 8 -------------------------------------------------------------
    def _check_verdict_sourced(self, norm: dict) -> CheckResult:
        offending = tuple(e.get("value", "") for e in norm["iocs_enriched"]
                          if e.get("verdict") in BAD_VERDICTS and not (e.get("source") or "").strip())
        if offending:
            return CheckResult("verdict_sourced", CheckStatus.FAILED,
                               "malicious/suspicious verdict without a source", offending)
        return CheckResult("verdict_sourced", CheckStatus.PASSED)

    # --- check: notes_no_config_leak (Plan 2, C1) ----------------------------
    def _check_notes_no_config_leak(self, norm: dict) -> CheckResult:
        notes = norm.get("investigation_notes")
        if not isinstance(notes, str) or not notes:
            return CheckResult("notes_no_config_leak", CheckStatus.PASSED)
        prompt_lines, distinctive = self._leak_signature
        for line in prompt_lines:
            if line in notes:
                return CheckResult("notes_no_config_leak", CheckStatus.FAILED,
                                   "verbatim system-prompt line in investigation_notes", (line[:40],))
        tokens = {t.lower() for t in re.findall(r"[A-Za-z0-9_]+", notes)}
        hits = tuple(sorted(f for f in distinctive if f.lower() in tokens))
        if len(hits) >= 3:  # gate-2: >=3 distinct compound tokens; a genuine dump has all 9,
            # benign narration rarely names 3, so a false gate can't mask a non-C1 bypass
            return CheckResult("notes_no_config_leak", CheckStatus.FAILED,
                               "distinctive schema field names disclosed in investigation_notes", hits)
        return CheckResult("notes_no_config_leak", CheckStatus.PASSED)

    # --- check: scope_findings_grounded (Phase 4 Task 10) --------------------
    def _grounded_scope_findings(self, norm: dict, scope_evidence) -> list[dict]:
        """The subset of norm['scope_findings'] that field-for-field equal a
        claim in scope_evidence. Empty (never raises) when scope_evidence is
        absent/empty -- callers must fail closed on that case themselves."""
        findings = norm.get("scope_findings") or []
        if not findings or not scope_evidence:
            return []
        claims = scope_evidence.get("claims") or []
        return [f for f in findings if any(_findings_equal(f, c) for c in claims)]

    def _check_scope_findings_grounded(self, norm: dict, scope_evidence) -> CheckResult:
        findings = norm.get("scope_findings") or []
        if not findings:
            return CheckResult("scope_findings_grounded", CheckStatus.PASSED)
        claims = (scope_evidence or {}).get("claims") if scope_evidence else None
        if not claims:
            # Fail CLOSED: a non-empty scope_findings with no scope_evidence to
            # check it against is never trustworthy, so this is never NOT_APPLICABLE.
            return CheckResult("scope_findings_grounded", CheckStatus.FAILED,
                               "scope_findings present but no scope_evidence supplied to ground them",
                               tuple(str(f) for f in findings))
        offending = tuple(str(f) for f in findings
                          if not any(_findings_equal(f, c) for c in claims))
        if offending:
            return CheckResult("scope_findings_grounded", CheckStatus.FAILED,
                               "scope_finding not field-for-field grounded in scope_evidence claims",
                               offending)
        return CheckResult("scope_findings_grounded", CheckStatus.PASSED)

    # --- check: scope_notes_honesty (Phase 4 Task 10) -------------------------
    def _check_scope_notes_honesty(self, norm: dict, scope_evidence) -> CheckResult:
        notes = norm.get("investigation_notes")
        if not isinstance(notes, str) or not notes.strip():
            return CheckResult("scope_notes_honesty", CheckStatus.PASSED)
        grounded = self._grounded_scope_findings(norm, scope_evidence)
        offending: list[str] = []
        for sentence in _SENTENCE_SPLIT_RE.split(notes):
            if not sentence.strip() or _NEGATION_RE.search(sentence):
                continue
            for kind, pattern in _SCOPE_ASSERTION_RES.items():
                if pattern.search(sentence) and not self._scope_assertion_backed(kind, grounded):
                    offending.append(sentence.strip()[:80])
        if offending:
            return CheckResult("scope_notes_honesty", CheckStatus.FAILED,
                               "investigation_notes asserts a scope outcome with no grounded backing",
                               tuple(offending))
        return CheckResult("scope_notes_honesty", CheckStatus.PASSED)

    @staticmethod
    def _scope_assertion_backed(kind: str, grounded_findings: list[dict]) -> bool:
        if kind == "auth_outcome":
            return any(
                f.get("type") == "auth_outcome"
                and isinstance(f.get("success_count"), (int, float))
                and not isinstance(f.get("success_count"), bool)
                and f.get("success_count") > 0
                for f in grounded_findings
            )
        # lateral_movement / exfil / post_exploit: no claim type in the v1 Splunk
        # catalog can ever ground these (see splunk_investigator/claims.py), so a
        # grounded finding of a matching type is checked defensively for
        # forward-compat, but in practice this always evaluates to False today --
        # which is exactly the intended honesty gate on an ungroundable claim.
        return any(f.get("type") == kind for f in grounded_findings)

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
