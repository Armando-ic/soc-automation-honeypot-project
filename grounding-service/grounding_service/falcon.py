"""Pure helpers for the 0D-2 Falcon Alerts poller + human-fired Contain.

Side-effect-free except load_state/save_state (a small JSON file alongside runs.jsonl
on the grounding_runs volume). Field names that were UNVERIFIED on us-2 until the
0D-2 §10 pre-build check are pinned as module constants (see
infra/honeypot/falcon-alerts-field-map.md).
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

# --- §10 pre-build-check-pinned field names (Task 0; update to match the live us-2 facts) ---
TS_FIELD = "created"                                    # hydrated-alert ISO timestamp key (watermark read field)
SRC_IP_FIELDS = ("external_ip", "local_ip", "src_ip")  # tried in order; first present + valid public IP wins
HOST_DEFAULT = "vm-honeypot-win"
CONSOLE_LINK_TEMPLATE = "https://falcon.us-2.crowdstrike.com/activity-v2/detections/{composite_id}"


def load_state(path) -> dict:
    p = Path(path)
    if not p.exists():
        return {"watermark": "", "seen": []}
    data = json.loads(p.read_text(encoding="utf-8"))
    data.setdefault("watermark", "")
    data.setdefault("seen", [])
    return data


def save_state(path, state: dict) -> None:
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(p)                                      # atomic replace on the same filesystem


def select_new_alert_ids(candidate_ids, seen, cap) -> list[str]:
    """Drop already-seen composite_ids (order-preserving) and cap to `cap` oldest-first."""
    seen_set = set(seen or [])
    fresh = [cid for cid in (candidate_ids or []) if cid not in seen_set]
    return fresh[: max(0, int(cap))]


def advance_state(state: dict, results, *, seen_max: int = 5000) -> dict:
    """Advance {watermark, seen} from per-alert results (oldest-first; each {composite_id, created, ok}).

    The watermark advances ONLY across the contiguous leading run of ok results, so a mid-batch
    failure never strands an earlier-but-unacked alert behind the watermark (prevents a SKIP).
    """
    watermark = state.get("watermark", "")
    seen = list(state.get("seen", []))
    for r in results:                                   # MUST be oldest-first
        if not r.get("ok"):
            break                                       # contiguous prefix only
        cid = r.get("composite_id")
        created = r.get("created", "")
        if cid and cid not in seen:
            seen.append(cid)
        if created and created > watermark:             # ISO8601 strings sort lexicographically
            watermark = created
    if len(seen) > seen_max:
        seen = seen[-seen_max:]
    return {"watermark": watermark, "seen": seen}
