# splunk_investigator/event_time.py
"""Canonicalize an alert's event_time into an ISO-8601 string the rest of the
engine (catalog.render_spl, pregate._dedup_key) can anchor on.

WHY THIS EXISTS (Phase 4 LB-1): the live honeypot saved search ends in
`| stats ... earliest(_time) as earliest, latest(_time) as latest by src_ip`,
which DROPS the raw `_time` field and emits epoch-seconds `earliest`/`latest`.
The webhook `result` row therefore carries no ISO `_time`, and a bare epoch
string is NOT accepted by datetime.fromisoformat -- so every time-bounded
catalog query used to render_error and produce no claim (grounding inert in
production). This turns whatever the alert actually carries (an ISO string
already, or Splunk epoch seconds) into ONE ISO string, and fail-closes to ''
for anything it can't parse so the existing '' -> render_error -> no-claim
fail-safe still holds -- never a wall-clock anchor, never a false window.

NOT a wall clock: the epoch->ISO branch uses datetime.fromtimestamp(..., tz=UTC),
a pure deterministic transform of the SUPPLIED value. Nothing here reads the
real clock, so the module keeps the engine's F-scope-time invariant intact.
"""
from __future__ import annotations

from datetime import datetime, timezone


def normalize_event_time(raw) -> str:
    """ISO passthrough, epoch-seconds -> timezone-AWARE UTC ISO, else ''.

    - An ISO-8601 string datetime.fromisoformat already accepts (naive, aware,
      or Z-suffixed) is returned UNCHANGED -- the shapes the engine already
      handled are preserved byte-for-byte, so this never re-derives them.
    - An epoch-seconds value (int/float, or a numeric string like Splunk's
      "1751500800" / "1751500800.000000") becomes a timezone-AWARE UTC ISO
      string (e.g. "2025-07-03T00:00:00+00:00"). The aware-ness is load-bearing:
      catalog.render_spl anchors an aware event_time as an ABSOLUTE instant
      (epoch Splunk bounds), which a non-UTC search head reads correctly -- a
      naive-UTC anchor would be misread as search-head-local and shift the
      window off the real event.
    - Anything else (None, '', unparseable text, out-of-range epoch) -> '' so
      the caller fail-closes to no-claim.

    Not a wall clock: the epoch->ISO branch uses datetime.fromtimestamp(..., tz=
    UTC), a pure deterministic transform of the SUPPLIED value.
    """
    if raw is None:
        return ""

    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return ""
        # Already an ISO string the engine's own parser accepts? Keep it verbatim.
        try:
            datetime.fromisoformat(s)
            return s
        except ValueError:
            pass  # not ISO -- maybe epoch seconds carried as a string; fall through
        raw = s  # normalized string for the numeric parse below

    # Epoch seconds (a number, or a numeric string).
    try:
        epoch = float(raw)
    except (TypeError, ValueError):
        return ""
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        # Absurd/out-of-range epoch -> fail closed rather than crash.
        return ""
