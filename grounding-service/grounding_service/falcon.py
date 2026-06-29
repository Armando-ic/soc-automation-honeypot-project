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

# --- §10 field names CONFIRMED on a live us-2 alert (2026-06-29; see falcon-alerts-field-map.md) ---
# The real Alerts v2 object has `timestamp` + `updated_timestamp` (no `created`); `created_timestamp`
# is the FQL sort/filter key (poller side) and is read first when present. The object has no top-level
# `composite_id` (= origin_cid + ":" + id) and no top-level filename/cmdline (use `name` + hashes).
TS_READ_FIELDS = ("created_timestamp", "timestamp")    # watermark read: first present wins (FQL key = created_timestamp)
IP_FIELDS = ("source_ips", "external_ip", "local_ip", "src_ip")  # source_ips is an array; first public IP wins
HOST_DEFAULT = "vm-honeypot-win"
CONSOLE_LINK_TEMPLATE = "https://falcon.us-2.crowdstrike.com/activity-v2/detections/{composite_id}"
_ZERO_HASH = re.compile(r"^0+$")                       # Falcon emits all-zero sha1/sha256 placeholders


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


def _iter_ip_candidates(alert: dict):
    for key in IP_FIELDS:
        v = alert.get(key)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            for elem in v:
                yield str(elem).strip()
        else:
            yield str(v).strip()


def _first_ip(alert: dict) -> str:
    for s in _iter_ip_candidates(alert):
        if s and _is_public_ip(s):
            return s
    return ""


def alert_created(alert: dict) -> str:
    """The watermark timestamp: first present of TS_READ_FIELDS (created_timestamp, then timestamp)."""
    for key in TS_READ_FIELDS:
        v = alert.get(key)
        if v:
            return str(v)
    return ""


def composite_id_of(alert: dict) -> str:
    """The composite_id is not a returned field; reconstruct it as origin_cid + ':' + id."""
    cid = alert.get("composite_id")
    if cid:
        return str(cid)
    oc, aid_id = alert.get("origin_cid"), alert.get("id")
    return f"{oc}:{aid_id}" if oc and aid_id else ""


def _file_hash(alert: dict) -> str:
    """A real (non-placeholder) file hash for the alert_text, sha256 preferred, else md5."""
    for key in ("sha256", "md5"):
        v = str(alert.get(key, "") or "")
        if v and not _ZERO_HASH.match(v):
            return v
    return ""


def map_alert(alert: dict) -> dict:
    """Falcon hydrated alert -> the EXISTING Splunk-shaped webhook body + additive keys (decision A').

    Field names confirmed on a live us-2 alert (falcon-alerts-field-map.md): the object exposes
    `name`/`tactic`/`technique`/`technique_id`/`severity_name`/`user_name`/`source_ips`/`sha256`/`md5`
    (no top-level filename/cmdline/composite_id).
    """
    sev_name = str(alert.get("severity_name", "") or "")
    tactic = str(alert.get("tactic", "") or "")
    technique = str(alert.get("technique", "") or "")
    technique_id = str(alert.get("technique_id", "") or "")
    name = str(alert.get("name", "") or "")
    user = str(alert.get("user_name", "") or "")
    src_ip = _first_ip(alert)
    file_hash = _file_hash(alert)
    composite_id = composite_id_of(alert)

    tac_tech = "/".join(p for p in (tactic, technique) if p)
    head = " ".join(p for p in (sev_name, tac_tech, f"({technique_id})" if technique_id else "") if p)
    alert_text = f"{head} on {HOST_DEFAULT}".strip()
    if name:
        alert_text += f" — {name}"
    if file_hash:
        alert_text += f" [hash {file_hash}]"
    if user:
        alert_text += f" (user {user})"

    label = technique or name or "detection"
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
