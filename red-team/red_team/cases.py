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
        "ioc_variant_passes",
    }
)

_VALID_SOURCES = frozenset({"splunk", "falcon"})
_VALID_RETRIEVAL = frozenset({"real", "pinned"})

# Per-source allowed `alert` keys = the DEPLOYED contract each source's transform
# actually reads. A case-authored `alert` key outside this set is dead weight: the
# pipeline silently drops it, so its payload never reaches the model and the case
# becomes a dud (C-2). The loader rejects such keys loudly at load time so a future
# author cannot re-introduce a `raw`-style (or wrong-shape) unread field.
#
# splunk: the fields red_team.harness.input_builder.splunk_body_from_case reads
#   (search_name, results_link) + result.{src_ip, user, ComputerName<-host, count}.
#   `console_link` is part of the deployed Parse Alert contract (parse_alert reads
#   body.console_link) and is kept allowed for parity.
_SPLUNK_ALERT_KEYS: frozenset[str] = frozenset(
    {"search_name", "results_link", "console_link", "src_ip", "user", "host", "count"}
)
# falcon: EXACTLY the keys grounding_service.falcon.map_alert (and its helpers)
#   read from a hydrated Falcon alert — severity_name/tactic/technique/technique_id/
#   name/user_name, the IP fields (source_ips/external_ip/local_ip/src_ip), the hash
#   fields (sha256/md5), the host fields (host_names/logon_domain), the composite-id
#   fields (composite_id/origin_cid/id), and the watermark timestamps. map_alert
#   CONSTRUCTS search_name/results_link/console_link/alert_text and does NOT read a
#   nested `result` dict or a top-level `source`, so those are NOT allowed here.
_FALCON_ALERT_KEYS: frozenset[str] = frozenset(
    {
        "severity_name", "tactic", "technique", "technique_id", "name", "user_name",
        "source_ips", "external_ip", "local_ip", "src_ip",
        "sha256", "md5",
        "host_names", "logon_domain",
        "composite_id", "origin_cid", "id",
        "created_timestamp", "timestamp",
    }
)
_ALERT_KEYS_BY_SOURCE: dict[str, frozenset[str]] = {
    "splunk": _SPLUNK_ALERT_KEYS,
    "falcon": _FALCON_ALERT_KEYS,
}

# Top-level keys the AttackCase(...) construction reads with strict `raw[...]`
# indexing. Validated up front so a missing key fails as a path-prefixed
# ValueError instead of a bare, context-free KeyError (M-1). `fixed_techniques`
# is intentionally excluded (read via .get()); it is guarded separately for the
# retrieval == 'pinned' case below.
_REQUIRED_TOP_LEVEL_KEYS: tuple[str, ...] = (
    "id",
    "class",
    "atlas",
    "source",
    "alert",
    "fixed_enrichment",
    "retrieval",
    "objective",
    "expected_correct",
    "win_condition",
)

# Each field-dependent predicate must have its backing `expected_correct` key
# present and non-empty (list) / truthy (contain_expected). Without this guard a
# typo'd or missing key makes the predicate silently short-circuit to False at
# scoring time, understating the very bypass rate the harness measures (I-1).
# The read semantics here mirror scorer.py exactly:
#   - the four list-backed predicates call `_as_list(expected_correct.get(KEY))`
#     and `return False` when the result is empty, so the key must be a
#     non-empty list.
#   - contain_suppressed does `if not expected_correct.get("contain_expected")`,
#     so the key must be present and truthy.
# `severity_below_expected` is deliberately NOT here: it keeps its own dedicated
# enum-checking branch below. NOTE: do not import scorer.py here (scorer imports
# cases -> cycle); this map is kept in lockstep with scorer.py by hand.
PREDICATE_REQUIRED_FIELD: dict[str, str] = {
    "hot_tactic_absent_from_retrieved": "hot_tactic_technique_ids",
    "injected_ioc_present": "injected_iocs",
    "real_ioc_absent_or_downgraded": "real_iocs",
    "ioc_variant_passes": "canonical_iocs",
    "contain_suppressed": "contain_expected",
}


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

    # Presence of every required top-level key, before any strict raw[...] read
    # in load_cases (M-1: bare KeyError -> path-prefixed ValueError).
    missing = [k for k in _REQUIRED_TOP_LEVEL_KEYS if k not in raw]
    if missing:
        fail(f"missing required key(s): {missing}")

    retrieval = raw.get("retrieval")
    if retrieval not in _VALID_RETRIEVAL:
        fail(f"retrieval must be one of {sorted(_VALID_RETRIEVAL)}, got {retrieval!r}")

    if retrieval == "pinned":
        fixed_techniques = raw.get("fixed_techniques")
        if not isinstance(fixed_techniques, list) or not fixed_techniques:
            fail("fixed_techniques must be a non-empty list when retrieval == 'pinned'")

    win_condition = raw.get("win_condition") or []
    if not win_condition:
        # A case with no win condition can never deviate -> corpus error (M-1).
        fail("win_condition must be a non-empty list")
    unknown = [p for p in win_condition if p not in KNOWN_PREDICATES]
    if unknown:
        fail(f"unknown predicate(s) in win_condition: {unknown}")

    source = raw.get("source")
    if source not in _VALID_SOURCES:
        fail(f"source must be one of {sorted(_VALID_SOURCES)}, got {source!r}")

    # Per-source alert-key contract guard (C-2): every `alert` key must be one the
    # deployed transform for this source actually reads, or its payload is silently
    # dropped and the case is a dud. Only enforced for a known source (validated
    # just above); an unknown source already failed.
    alert = raw.get("alert")
    if isinstance(alert, dict) and source in _ALERT_KEYS_BY_SOURCE:
        allowed = _ALERT_KEYS_BY_SOURCE[source]
        unread = sorted(k for k in alert if k not in allowed)
        if unread:
            fail(
                f"alert has key(s) not in the deployed {source} contract "
                f"(payload in an unread key never reaches the model): {unread}. "
                f"Allowed {source} alert keys: {sorted(allowed)}"
            )

    expected_correct = raw.get("expected_correct") or {}

    if "severity_below_expected" in win_condition:
        severity = expected_correct.get("severity")
        if severity not in SEVERITIES:
            fail(
                "expected_correct.severity must be one of "
                f"{SEVERITIES} when severity_below_expected is used, got {severity!r}"
            )

    # Per-predicate backing-field guard (I-1): each field-dependent predicate in
    # win_condition must have its non-empty/truthy backing expected_correct key,
    # or it would silently score False at run time.
    for predicate, field in PREDICATE_REQUIRED_FIELD.items():
        if predicate not in win_condition:
            continue
        value = expected_correct.get(field)
        if predicate == "contain_suppressed":
            if not value:
                fail(
                    f"expected_correct.{field} must be truthy when "
                    f"{predicate} is used, got {value!r}"
                )
        else:
            if not isinstance(value, list) or not value:
                fail(
                    f"expected_correct.{field} must be a non-empty list when "
                    f"{predicate} is used, got {value!r}"
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
