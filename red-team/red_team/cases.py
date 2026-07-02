"""Attack-case schema + YAML loader for the Phase 1 red-team harness.

Every adversarial scenario in `red-team/cases/` (and later `held_out/`)
deserializes into an `AttackCase`. The predicate grammar used in a case's
`win_condition` is CLOSED (`KNOWN_PREDICATES`): a typo'd or invented predicate
must fail loudly at load time rather than silently never matching during
scoring (Task 10 consumes these cases and evaluates win_condition predicates
against a transcript).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from triage_verifier.constants import SEVERITIES

# The closed predicate grammar. `verdict_is` is intentionally absent — it was
# an unused orphan predicate from an earlier draft of the design (§16 item 1).
KNOWN_PREDICATES: frozenset[str] = frozenset(
    {
        "severity_below_expected",
        "malicious_ioc_marked_clean",
        "cites_technique_not_in_retrieved",
        "hot_tactic_absent_from_retrieved",
        "injected_ioc_present",
        "real_ioc_absent_or_downgraded",
        "contain_suppressed",
        "notes_leak_prompt",
        "output_contains_discord_mention",
        "output_not_json_safe",
        "ioc_variant_passes",
    }
)

_VALID_SOURCES = frozenset({"splunk", "falcon"})
_VALID_RETRIEVAL = frozenset({"real", "pinned"})


@dataclass(frozen=True)
class AttackCase:
    id: str
    class_: str
    atlas: str
    source: str
    alert: dict[str, Any]
    fixed_enrichment: dict[str, Any]
    retrieval: str
    fixed_techniques: list[str] | None
    objective: str
    expected_correct: dict[str, Any]
    win_condition: list[str]


def _validate(raw: dict[str, Any], path: Path) -> None:
    """Validate a raw parsed YAML dict, failing loudly (ValueError) on any
    schema violation. Errors are prefixed with the source path for debugging
    a large seed corpus."""

    def fail(msg: str) -> None:
        raise ValueError(f"{path}: {msg}")

    retrieval = raw.get("retrieval")
    if retrieval not in _VALID_RETRIEVAL:
        fail(f"retrieval must be one of {sorted(_VALID_RETRIEVAL)}, got {retrieval!r}")

    if retrieval == "pinned":
        fixed_techniques = raw.get("fixed_techniques")
        if not isinstance(fixed_techniques, list) or not fixed_techniques:
            fail("fixed_techniques must be a non-empty list when retrieval == 'pinned'")

    win_condition = raw.get("win_condition") or []
    unknown = [p for p in win_condition if p not in KNOWN_PREDICATES]
    if unknown:
        fail(f"unknown predicate(s) in win_condition: {unknown}")

    source = raw.get("source")
    if source not in _VALID_SOURCES:
        fail(f"source must be one of {sorted(_VALID_SOURCES)}, got {source!r}")

    if "severity_below_expected" in win_condition:
        severity = (raw.get("expected_correct") or {}).get("severity")
        if severity not in SEVERITIES:
            fail(
                "expected_correct.severity must be one of "
                f"{SEVERITIES} when severity_below_expected is used, got {severity!r}"
            )


def load_cases(directory: Path) -> list[AttackCase]:
    """Load every `*.yaml` file directly under `directory` (non-recursive —
    a future `held_out/` subdirectory is loaded separately) into validated
    `AttackCase` instances."""
    cases: list[AttackCase] = []
    for path in sorted(directory.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        _validate(raw, path)
        cases.append(
            AttackCase(
                id=raw["id"],
                class_=raw["class"],
                atlas=raw["atlas"],
                source=raw["source"],
                alert=raw["alert"],
                fixed_enrichment=raw["fixed_enrichment"],
                retrieval=raw["retrieval"],
                fixed_techniques=raw.get("fixed_techniques"),
                objective=raw["objective"],
                expected_correct=raw["expected_correct"],
                win_condition=raw["win_condition"],
            )
        )
    return cases
