"""Pure helpers for the 0D-2 Falcon Alerts poller + human-fired Contain.

Side-effect-free except load_state/save_state (a small JSON file alongside runs.jsonl
on the grounding_runs volume). Field names that were UNVERIFIED on us-2 until the
0D-2 §10 pre-build check are pinned as module constants (see
infra/honeypot/falcon-alerts-field-map.md).
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

# Internal/non-routable filter — mirrors honeypot-triage Parse Alert's isPrivate (RFC1918 + loopback +
# link-local) on purpose: both feed the same canonical IOC path, so they must accept/reject identically.
# (Deliberately NOT ipaddress.is_private, which over-rejects documentation ranges on Python 3.12+.)
_PRIVATE_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|169\.254\.)")

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


def _is_public_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)              # validate shape (rejects non-IPs)
    except ValueError:
        return False
    return _PRIVATE_RE.match(value) is None      # routable external IP (RFC1918/loopback/link-local excluded)


def _first_ip(alert: dict) -> str:
    for key in SRC_IP_FIELDS:
        v = alert.get(key)
        if not v:
            continue
        s = str(v).strip()
        if _is_public_ip(s):
            return s
    return ""


def map_alert(alert: dict) -> dict:
    """Falcon hydrated alert -> the EXISTING Splunk-shaped webhook body + additive keys (decision A')."""
    sev_name = str(alert.get("severity_name", "") or "")
    tactic = str(alert.get("tactic", "") or "")
    technique = str(alert.get("technique", "") or "")
    technique_id = str(alert.get("technique_id", "") or "")
    filename = str(alert.get("filename", "") or "")
    cmdline = str(alert.get("cmdline", "") or "").strip()
    if len(cmdline) > 200:
        cmdline = cmdline[:200] + "…"
    user = str(alert.get("user_name", "") or "")
    src_ip = _first_ip(alert)
    composite_id = str(alert.get("composite_id", "") or "")

    tac_tech = "/".join(p for p in (tactic, technique) if p)
    head = " ".join(p for p in (sev_name, tac_tech, f"({technique_id})" if technique_id else "") if p)
    tail = " — ".join(p for p in (filename, cmdline) if p)
    alert_text = f"{head} on {HOST_DEFAULT}".strip()
    if tail:
        alert_text += f" — {tail}"
    if user:
        alert_text += f" (user {user})"

    label = technique or "detection"
    search_name = f"Falcon — {label} ({sev_name})" if sev_name else f"Falcon — {label}"
    console_link = CONSOLE_LINK_TEMPLATE.format(composite_id=composite_id) if composite_id else ""

    return {
        "search_name": search_name,
        "results_link": console_link,
        "console_link": console_link,
        "source": "falcon",
        "alert_text": alert_text,
        "result": {"src_ip": src_ip, "user": user, "ComputerName": HOST_DEFAULT, "count": 1},
    }


def select_contain_aid(resolved_ids, pinned_aid: str) -> str:
    """Return the single safe AID to contain, or raise ValueError. Hostname is NOT a boundary; the pin is."""
    if not pinned_aid:
        raise ValueError("FALCON_PINNED_AID is not configured — refusing to contain")
    ids = list(resolved_ids or [])
    if len(ids) != 1:
        raise ValueError(f"expected exactly one host for the hostname, got {len(ids)}")
    if ids[0] != pinned_aid:
        raise ValueError("resolved AID does not match the pinned honeypot AID — refusing to contain")
    return ids[0]
