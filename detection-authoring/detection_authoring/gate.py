"""The deterministic 4-tier gate (spec section 6). Pure function of
(yaml_text, frozen corpus): no network, no Qdrant, no Claude."""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from detection_authoring.compile import compile_spl, parse_errors
from detection_authoring.corpus import load_benign, load_positives
from detection_authoring.matcher import matches
from detection_authoring.sigma_subset import check_supported


# Sanity bounds on candidate YAML before any parser sees it. A real Sigma rule
# is small and shallow (a few nested levels); anything past these bounds is not a
# plausible drafter rule and could exhaust a parser stack. Deep enough nesting
# overflows libyaml's C stack (via pySigma) and kills the whole process, which no
# try/except can catch, so the only safe defense is to reject it up front.
_MAX_YAML_CHARS = 100_000
_MAX_YAML_NESTING = 100


def _exceeds_limits(yaml_text: str) -> bool:
    """True if yaml_text is too large or nests deeper than the gate will hand to
    a parser. Nesting is measured syntax-independently from PyYAML's event stream
    (block, flow, and compact '-' sequences all count) using the pure-Python
    parser, which walks an explicit state stack and so cannot C-stack-overflow
    the way pySigma's libyaml loader can. Bails as soon as the limit is crossed,
    so a pathological document costs O(limit), not O(input)."""
    if len(yaml_text) > _MAX_YAML_CHARS:
        return True
    depth = 0
    try:
        for event in yaml.parse(yaml_text):
            if isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                depth += 1
                if depth > _MAX_YAML_NESTING:
                    return True
            elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                depth -= 1
    except RecursionError:
        return True  # pathological even for the safe event parser
    except yaml.YAMLError:
        return False  # ordinary malformed-but-shallow doc; let the tier path report it
    return False


@dataclass
class GateResult:
    t1_parse_ok: bool = False
    t1_parse_errors: list[str] = field(default_factory=list)
    subset_ok: bool = False
    unsupported: list[str] = field(default_factory=list)
    t2_compile_ok: bool = False
    spl: str | None = None
    t3_tp_ok: bool = False
    positives_matched: list[bool] = field(default_factory=list)
    t4_tn_ok: bool = False
    benign_false_positives: list[dict] = field(default_factory=list)
    passed: bool = False


def run_gate(yaml_text: str, technique_id: str) -> GateResult:
    """Run the deterministic 4-tier gate over candidate Sigma YAML and return a
    GateResult. Never raises on the yaml_text side (untrusted, LLM-drafted text
    can be malformed or well-formed-but-non-mapping) - any parse problem routes
    to a failing verdict, and pathologically large or deeply-nested input is
    rejected up front before it can exhaust a parser stack. This totality covers
    plausible drafter output and arbitrary nesting depth; it is not a hardened
    defense against deliberately adversarial YAML (e.g. alias/anchor expansion
    bombs), which is outside the lab threat model.

    technique_id must have a frozen positive corpus (see corpus/positives/); a
    missing one raises FileNotFoundError by design, surfacing misconfiguration
    rather than silently corrupting the verdict.
    """
    res = GateResult()

    # Reject pathologically large or deeply-nested input before any parser sees
    # it: otherwise a plain RecursionError or an uncatchable native libyaml stack
    # overflow (via parse_errors) escapes the tier guards below.
    if _exceeds_limits(yaml_text):
        res.unsupported = ["rule is too large or too deeply nested to evaluate"]
        return res

    # T1: valid Sigma
    res.t1_parse_errors = parse_errors(yaml_text)
    res.t1_parse_ok = not res.t1_parse_errors

    # Subset guard needs a plain dict (pySigma's SigmaRule loader above already
    # parsed yaml_text for T1; this second, raw yaml.safe_load is intentional -
    # check_supported() walks a plain mapping, not a SigmaRule object).
    try:
        rule_dict = yaml.safe_load(yaml_text) or {}
    except Exception as exc:
        # Broad on purpose: safe_load can raise RecursionError (not a
        # yaml.YAMLError) on nesting the up-front guard did not catch, plus the
        # ordinary YAML parse errors. Any of them routes to a failing verdict.
        res.unsupported = [f"yaml load failed: {exc}"]
        return res
    if not isinstance(rule_dict, dict):
        res.unsupported = [f"rule is not a mapping: {type(rule_dict).__name__}"]
        return res
    try:
        res.unsupported = check_supported(rule_dict)
    except Exception as exc:
        # check_supported assumes mapping-shaped logsource/detection/selections;
        # untrusted drafter YAML can nest a list or a non-string key one level
        # down. Any structural surprise routes to a failing verdict, keeping
        # run_gate total over the yaml_text side (mirrors compile.py's except).
        res.unsupported = [f"malformed rule structure: {exc}"]
        return res
    res.subset_ok = not res.unsupported

    # T2: compiles to SPL (independent of T3/T4)
    res.spl = compile_spl(yaml_text)
    res.t2_compile_ok = res.spl is not None

    # T3/T4 only run when the rule is inside the subset the matcher models.
    if res.subset_ok and res.t1_parse_ok:
        detection = rule_dict["detection"]
        # Corpus loads stay outside the try: a missing frozen corpus for
        # technique_id is a config precondition failure, loud by design.
        positives = load_positives(technique_id)
        benign = load_benign()
        try:
            res.positives_matched = [matches(detection, ev) for ev in positives]
            res.t3_tp_ok = all(res.positives_matched) and len(positives) > 0
            res.benign_false_positives = [ev for ev in benign if matches(detection, ev)]
            res.t4_tn_ok = not res.benign_false_positives
        except Exception as exc:
            # The subset guard is meant to admit only rules the matcher can
            # evaluate, but the two do not model the condition grammar
            # identically (e.g. a bare wildcard selection token with no
            # quantifier). If the matcher can't evaluate a rule the guard let
            # through, the rule is not faithfully in the modeled subset: fail it
            # and record why, rather than raising out of run_gate.
            res.unsupported.append(f"matcher could not evaluate rule: {exc}")
            res.subset_ok = False
            res.t3_tp_ok = False
            res.t4_tn_ok = False

    res.passed = res.t1_parse_ok and res.subset_ok and res.t2_compile_ok and res.t3_tp_ok and res.t4_tn_ok
    return res
