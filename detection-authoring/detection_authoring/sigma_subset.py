"""Declare the supported Sigma subset and check a parsed rule dict against it.

Returns a list of human-readable strings naming each unsupported feature.
Empty list means the rule is fully within the subset the owned matcher models,
which is the precondition for running T3/T4 faithfully.
"""
from __future__ import annotations

from detection_authoring.sysmon_fields import ALLOWED_FIELDS

SUPPORTED_CATEGORY = "process_creation"
SUPPORTED_PRODUCT = "windows"
SUPPORTED_MODIFIERS: frozenset[str] = frozenset(
    {"contains", "startswith", "endswith", "all", "re"}
)
_CONDITION_WORDS = {"and", "or", "not", "of", "them", "1", "all"}


def check_supported(rule_dict: dict) -> list[str]:
    findings: list[str] = []

    logsource = rule_dict.get("logsource", {}) or {}
    if logsource.get("product") != SUPPORTED_PRODUCT:
        findings.append(f"logsource.product must be '{SUPPORTED_PRODUCT}', got {logsource.get('product')!r}")
    if logsource.get("category") != SUPPORTED_CATEGORY:
        findings.append(f"logsource.category must be '{SUPPORTED_CATEGORY}', got {logsource.get('category')!r}")

    detection = rule_dict.get("detection", {}) or {}
    if not [n for n in detection if n != "condition"]:
        # A detection with zero selections makes "all of them" vacuously match
        # everything (all([]) is True), so reject it here rather than let the
        # matcher silently match-all.
        findings.append("detection defines no selections")
    for name, sel in detection.items():
        if name == "condition":
            continue
        if not isinstance(sel, dict):
            findings.append(f"selection '{name}' must be a field:value mapping (keyword lists unsupported)")
            continue
        for field_expr in sel:
            parts = field_expr.split("|")
            field, mods = parts[0], parts[1:]
            if field not in ALLOWED_FIELDS:
                findings.append(f"field '{field}' not in the allowed Sysmon field set")
            for mod in mods:
                if mod not in SUPPORTED_MODIFIERS:
                    findings.append(f"modifier '{mod}' on '{field}' is outside the supported subset")

    condition = detection.get("condition")
    if not isinstance(condition, str):
        findings.append("condition must be a single string expression")
    else:
        names = {n for n in detection if n != "condition"}
        for tok in condition.replace("(", " ").replace(")", " ").split():
            low = tok.lower()
            if low in _CONDITION_WORDS:
                continue
            base = tok.rstrip("*")
            matches_a_selection = any(n == tok or (tok.endswith("*") and n.startswith(base)) for n in names)
            if not matches_a_selection:
                findings.append(f"condition token '{tok}' is not a known selection or supported keyword")
    return findings
