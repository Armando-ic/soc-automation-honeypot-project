"""Pregate: the short-circuit that runs BEFORE any paid Claude call.

Pure function - no I/O, no Anthropic, no splunklib, no wall clock. Consumes
only `config.Config` plus caller-supplied dedup/budget state. Checked in this
precedence, first hit wins:

1. kill switch (cfg.enabled is False) - wins over everything.
2. no pivotable entity (no host and no PUBLIC src_ip).
3. dedup (src_ip + coarse event_time window already seen).
4. daily budget exhausted.

This filters no-pivot traffic, not benign traffic. A brute-force alert with a
public src_ip SHOULD pass and pay for the investigation loop - that's the
point of the project. Do not add a "looks benign" shortcut here.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from .config import Config
from .event_time import normalize_event_time

# Every attribute here must be False for an address to count as "public".
_NON_PUBLIC_ATTRS = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_reserved",
    "is_unspecified",
    "is_multicast",
)

# Treated as the origin for bucketing naive event_time strings. Using a fixed
# epoch (rather than datetime.timestamp(), which interprets naive datetimes in
# the SYSTEM local timezone) keeps the bucket deterministic regardless of what
# machine/TZ this runs on.
_EPOCH = datetime(1970, 1, 1)


def _is_public_ip(value: str | None) -> bool:
    """True only for a genuinely public, routable IP address."""
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(getattr(addr, attr) for attr in _NON_PUBLIC_ATTRS)


def _dedup_key(alert: dict, cfg: Config) -> str:
    """Deterministic (src_ip, coarse-window) key. No wall clock ever - the
    window is floored from the ALERT's own event_time, per Task 3's
    event-anchoring rule. Falls back to a src_ip-only key if event_time is
    missing/unparseable (still deterministic, just coarser).
    """
    src_ip = alert.get("src_ip") or ""
    # LB-1 consistency: normalize the SAME way agent.investigate does (epoch->ISO,
    # ISO passthrough, else '') so both event_time consumers agree on the live
    # shape. Without this a raw epoch event_time would fail fromisoformat here and
    # coarsen every alert to the src_ip-only bucket.
    event_time = normalize_event_time(alert.get("event_time"))
    if event_time:
        try:
            event_dt = datetime.fromisoformat(event_time)
        except (ValueError, TypeError):
            event_dt = None
        if event_dt is not None:
            if event_dt.tzinfo is not None:
                # Offset arithmetic only (not wall-clock): normalize to UTC
                # deterministically so two logically-simultaneous timestamps
                # expressed with different offsets land in the same bucket.
                event_dt = event_dt.astimezone(timezone.utc).replace(tzinfo=None)
            bucket = int((event_dt - _EPOCH).total_seconds()) // cfg.per_source_window_s
            return f"{src_ip}|{bucket}"
    return f"{src_ip}|no-event-time"


def should_investigate(
    alert: dict,
    cfg: Config,
    *,
    seen: set[str] | None = None,
    day_count: int = 0,
) -> tuple[bool, str]:
    if not cfg.enabled:
        return False, "kill_switch"

    host = alert.get("host") or ""
    src_ip = alert.get("src_ip") or ""
    if not host and not _is_public_ip(src_ip):
        return False, "no_pivot"

    if seen is not None and _dedup_key(alert, cfg) in seen:
        return False, "deduped"

    if day_count >= cfg.daily_budget:
        return False, "budget_exhausted"

    return True, ""
