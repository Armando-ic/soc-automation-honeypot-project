"""Repair misshapen submit_triage_result input before verification.

Every repair is recorded in repair_events and never silently erased.
"""
from __future__ import annotations

import copy

_LIST_FIELDS = ("mitre_techniques", "iocs_enriched", "recommended_actions")
_IOC_BUCKETS = ("ips", "domains", "file_hashes", "users", "hosts")


def _as_list(value: object) -> list:
    if isinstance(value, list):
        return value
    return [value]


def normalize_triage_result(raw: dict) -> tuple[dict, list[dict]]:
    result = copy.deepcopy(raw)
    events: list[dict] = []

    for field in _LIST_FIELDS:
        if field not in result:
            result[field] = []
            events.append({"field": field, "action": "added empty list"})
        elif not isinstance(result[field], list):
            result[field] = _as_list(result[field])
            events.append({"field": field, "action": "coerced scalar to list"})

    iocs = result.get("iocs")
    if not isinstance(iocs, dict):
        iocs = {}
        result["iocs"] = iocs
        events.append({"field": "iocs", "action": "added empty object"})
    for bucket in _IOC_BUCKETS:
        if not isinstance(iocs.get(bucket), list):
            iocs[bucket] = []
            events.append({"field": f"iocs.{bucket}", "action": "added empty list"})

    return result, events
