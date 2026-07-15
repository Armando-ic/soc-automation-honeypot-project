# grounding-service/grounding_service/feed_state.py
"""Feeder liveness watermark: proof that a brake feeder is ALIVE, not merely quiet.

WHY THIS EXISTS. evaluate_egress is stateless per call and answers a quiet box and a dead feeder
IDENTICALLY -- both are {"trip": False, "distinct_dst": 0, "conn_count": 0}. That is not a bug in
the brake; it genuinely cannot know. And on this honeypot the healthy state IS the ambiguous one:
measured live 2026-07-15, 24h of real telemetry produced ZERO rows on the watched ports, because
SwiftOnSecurity's NetworkConnect include covers neither svchost.exe nor ports 80/443. So "the
feeder reports nothing" is simultaneously the expected steady state and the total-failure state.

The resolution is that liveness is proven by ARRIVAL, not by content. A live feeder POSTS every
minute even with nothing to report, so a watermark over CALLS separates the two cases.

THREE DESIGN CONSTRAINTS, each learned the hard way:

* SOC-SIDE, NOT HONEYPOT-SIDE. A trip severs the feeder's own input: the brake's deny rule goes
  in at priority 100 with protocol/port "*", allow-splunk-telemetry sits at 1000, and lowest
  priority wins -- so a trip kills the honeypot's 9997 forwarding. Every honeypot-side signal
  dies exactly when it matters most. This state lives with grounding-service and survives.

* THE CLOCK IS ALWAYS INJECTED. `now` is a required keyword argument; nothing here calls
  datetime.now(). The two known-red falcon watermark tests are red precisely because load_state
  falls back to wall-clock at the endpoint boundary, so their assertions rot against real time.

* IT MUST NEVER BE ABLE TO BREAK THE BRAKE. /brake/evaluate is on the proven fire path, and an
  exception there routes out the evaluate node's error output into nsg_deny -- i.e. a telemetry
  bug would DENY ALL EGRESS and contain the box. Every function here degrades rather than raises,
  and the caller wraps it besides. Liveness telemetry is never worth strangling the honeypot for.

READ THE STALENESS SIGNAL HONESTLY. `stale` means "no feeder has posted recently", which is a
real alarm. But after a legitimate trip it will ALSO go stale forever, because the trip severs
the telemetry that feeds it. Stale therefore means "the feeder is not reporting", NOT "the feeder
is broken" -- check whether the brake has fired before treating it as a fault.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

_EMPTY: dict = {"last_post_at": "", "total_posts": 0, "recent": []}
DEFAULT_KEEP = 2000          # ~33h at one post/minute; bounded, and the newest is what matters


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_feed_state(path) -> dict:
    """Read the watermark. A missing, unreadable or corrupt file degrades to empty, never raises.

    Empty reads as "never posted", which summarize() reports as STALE -- the fail-safe direction.
    """
    try:
        p = Path(path)
        if not p.exists():
            return dict(_EMPTY, recent=[])
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return dict(_EMPTY, recent=[])
        recent = data.get("recent")
        return {
            "last_post_at": str(data.get("last_post_at", "") or ""),
            "total_posts": int(data.get("total_posts", 0) or 0),
            "recent": list(recent) if isinstance(recent, list) else [],
        }
    except Exception:
        return dict(_EMPTY, recent=[])


def save_feed_state(path, state: dict) -> None:
    """Atomic write, mirroring falcon.save_state: temp file then replace on the same filesystem."""
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(p)


def record_post(state: dict, *, now: datetime, distinct_dst: int, conn_count: int,
                source: str, trip: bool, keep: int = DEFAULT_KEEP) -> dict:
    """Append one feeder call. Pure: returns a new state, touches no disk and no clock.

    A quiet box (distinct_dst 0) records exactly like any other call. That IS the point.
    """
    entry = {"at": _stamp(now), "distinct_dst": int(distinct_dst), "conn_count": int(conn_count),
             "source": str(source or ""), "trip": bool(trip)}
    recent = list(state.get("recent") or [])
    recent.append(entry)
    keep = max(1, int(keep))
    return {
        "last_post_at": entry["at"],
        # total_posts counts EVERY post ever, independent of the ring: the ring answers "what has
        # the traffic looked like lately", the counter answers "has this thing ever worked".
        "total_posts": int(state.get("total_posts", 0) or 0) + 1,
        "recent": recent[-keep:],          # drop the OLDEST; the newest is the useful window
    }


def summarize(state: dict, *, now: datetime, stale_after_s: int) -> dict:
    """Render the watermark for /brake/feed-status. Pure; `now` injected.

    max_distinct_dst is the load-bearing field for the OPEN box: BRAKE_DISTINCT_DST_MAX=25 has
    never been measured with an attacker present (the closed-box baseline is 0, which is the
    regime where the feeder does not matter). This is what answers it with data.
    """
    recent = [r for r in (state.get("recent") or []) if isinstance(r, dict)]
    last = str(state.get("last_post_at", "") or "")

    age = None
    if last:
        try:
            parsed = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo)
            age = int(now.timestamp() - parsed.timestamp())
        except (ValueError, TypeError):
            age = None            # unparseable stamp -> unknown age -> stale, see below

    return {
        "last_post_at": last,
        "age_seconds": age,
        # FAIL-SAFE: never posted, or an age we cannot compute, is STALE. Absence of evidence is
        # not evidence of health -- a feeder that has never posted is the most broken state there
        # is, and it must not read green just because nothing contradicts it.
        "stale": age is None or age > int(stale_after_s),
        "total_posts": int(state.get("total_posts", 0) or 0),
        "samples": len(recent),
        "max_distinct_dst": max((int(r.get("distinct_dst", 0) or 0) for r in recent), default=0),
        "trips": sum(1 for r in recent if r.get("trip")),
    }
