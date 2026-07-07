"""Draft a Sigma rule with Claude, grounded in the pack, constrained to the
supported subset. Returns raw YAML text for the gate to judge; no trust is
placed in the draft here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from detection_authoring.config import load_config
from detection_authoring.context import GroundingPack

MAX_TOKENS = 4096
_FENCE_RE = re.compile(r"```(?:yaml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


@dataclass
class DraftResult:
    yaml_text: str | None
    outcome: str  # "ok" | "no_rule" | "refusal" | "truncated"


def build_system_prompt(pack: GroundingPack) -> str:
    fields = ", ".join(pack.allowed_fields)
    return (
        "You are a senior detection engineer. Write ONE Sigma detection rule for the "
        "given MITRE ATT&CK technique. Output the rule as a single fenced ```yaml block "
        "and nothing else.\n\n"
        "Hard constraints:\n"
        "- logsource MUST be {product: windows, category: process_creation}.\n"
        f"- Reference ONLY these fields: {fields}.\n"
        "- Allowed field modifiers: contains, startswith, endswith, all, re. "
        "Plain equals may use * and ? wildcards.\n"
        "- Each selection MUST be a single YAML mapping of field:value entries (all "
        "AND-ed together). Do NOT write a selection as a YAML list of mappings. To "
        "match alternatives across different fields (a logical OR), define separate "
        "named selections and combine them with 'or' in the condition. A single "
        "field's value MAY be a YAML list, which ORs the values for that one field. "
        "For example:\n"
        "    sel_image:\n"
        "      Image|endswith: '\\powershell.exe'\n"
        "    sel_origname:\n"
        "      OriginalFileName: 'powershell.exe'\n"
        "    condition: sel_image or sel_origname\n"
        "- condition may use named selections with and / or / not / parentheses / "
        "'1 of <pattern>' / 'all of <pattern>' / '1 of them' / 'all of them'.\n"
        "- The rule must fire on the technique's real behavior but stay quiet on "
        "ordinary administrator activity.\n"
        f"- Include tags: attack.{pack.tactics[0]} and attack.{pack.technique_id.lower()}.\n"
    )


def _build_user_message(pack: GroundingPack) -> str:
    neighbors = ", ".join(f"{n.get('id')} {n.get('name')}" for n in pack.neighbors) or "none"
    return (
        f"Technique: {pack.technique_id} - {pack.name}\n"
        f"Tactics: {', '.join(pack.tactics)}\n"
        f"Description: {pack.description}\n"
        f"Related techniques (for disambiguation, do not detect these): {neighbors}\n"
    )


def _extract_yaml(text: str) -> str | None:
    m = _FENCE_RE.search(text)
    if m:
        return m.group(1).strip()
    stripped = text.strip()
    if stripped.startswith("title:"):
        return stripped
    return None


def draft_rule(pack: GroundingPack, client) -> DraftResult:
    cfg = load_config()
    raw = client.messages.create(
        model=cfg.model,
        max_tokens=MAX_TOKENS,
        system=build_system_prompt(pack),
        messages=[{"role": "user", "content": _build_user_message(pack)}],
    )
    stop_reason = getattr(raw, "stop_reason", None)
    if stop_reason == "max_tokens":
        return DraftResult(None, "truncated")
    if stop_reason == "refusal":
        return DraftResult(None, "refusal")
    text = " ".join(getattr(b, "text", "") for b in getattr(raw, "content", []) or [])
    yaml_text = _extract_yaml(text)
    if yaml_text is None:
        return DraftResult(None, "no_rule")
    return DraftResult(yaml_text, "ok")
