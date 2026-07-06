"""Aggregate K authoring runs per technique into a markdown report (the
portfolio evidence, same spirit as red-team baseline-*.md). Separates gate
FAILs from INVALID model outcomes (no_rule/refusal/truncated)."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from detection_authoring.stats import clopper_pearson

_INVALID = {"no_rule", "refusal", "truncated"}


@dataclass
class AuthoringRun:
    technique_id: str
    passed: bool
    first_fail_tier: str | None   # e.g. "t3_tp", "t4_tn", "subset", "t2_compile", None
    outcome: str                  # "ok" | "no_rule" | "refusal" | "truncated"


def build_authoring_report(runs: list[AuthoringRun]) -> str:
    by_tid: dict[str, list[AuthoringRun]] = defaultdict(list)
    for r in runs:
        by_tid[r.technique_id].append(r)

    lines = ["# Phase 2 authoring report", ""]
    lines.append("| Technique | Passed | Pass-rate | 95% CI | Tier failures | Invalid |")
    lines.append("|---|---|---|---|---|---|")
    for tid in sorted(by_tid):
        group = by_tid[tid]
        valid = [r for r in group if r.outcome not in _INVALID]
        invalid = [r for r in group if r.outcome in _INVALID]
        k = sum(1 for r in valid if r.passed)
        n = len(valid)
        lo, hi = clopper_pearson(k, n) if n else (0.0, 0.0)
        tiers = defaultdict(int)
        for r in valid:
            if not r.passed and r.first_fail_tier:
                tiers[r.first_fail_tier] += 1
        tier_str = ", ".join(f"{t}:{c}" for t, c in sorted(tiers.items())) or "-"
        inv = defaultdict(int)
        for r in invalid:
            inv[r.outcome] += 1
        inv_str = ", ".join(f"{o}:{c}" for o, c in sorted(inv.items())) or "-"
        rate = f"{k}/{n}" if n else "0/0"
        lines.append(f"| {tid} | {'yes' if k else 'no'} | {rate} | [{lo:.2f}, {hi:.2f}] | {tier_str} | {inv_str} |")
    return "\n".join(lines) + "\n"
