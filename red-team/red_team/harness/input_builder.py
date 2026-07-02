"""Port of the deployed n8n `Parse Alert` Code node (JS_PARSE) to Python.

Source of truth: `JS_PARSE` in `infra/honeypot/build_honeypot_triage_workflow.py`
(lines 88-126 as of this port). This must reproduce that transform byte-for-byte
so the red-team harness feeds attack cases through the SAME logic the deployed
`honeypot-triage` n8n workflow runs. Do not "clean up" the JS `||`-falsy
semantics below — they are load-bearing (e.g. `count` must never be coerced to
int, since `0` and `""` both mean "missing" in JS but are valid values here).

`run_id` and `timestamp` replace the JS `$execution.id` / `new Date().toISOString()`
calls (non-deterministic in production); the harness injects them explicitly.
"""
from __future__ import annotations

import re

_PRIVATE_IP_RE = re.compile(
    r"^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\.|^127\."
)


def _is_private(ip: str) -> bool:
    """Mirror the JS isPrivate regex; empty string counts as private."""
    return ip == "" or bool(_PRIVATE_IP_RE.match(ip))


def parse_alert(
    body: dict,
    *,
    run_id: str = "rt-run",
    timestamp: str = "1970-01-01T00:00:00Z",
) -> dict:
    """Port of JS_PARSE. `body` is the ALREADY-unwrapped webhook body (i.e. what
    the JS calls `$input.first().json.body`) -- do not index another `.body`."""
    r = body.get("result") or {}
    source = body.get("source") or "splunk"

    src_ip = str(r.get("src_ip") or "").strip()
    host = r.get("ComputerName") or r.get("dest") or r.get("host") or "unknown-host"
    user = r.get("user") or r.get("Account_Name") or "unknown-user"
    count = r.get("count") or "multiple"

    enrich_ips = [src_ip] if (src_ip and not _is_private(src_ip)) else []

    if source == "falcon" and body.get("alert_text"):
        alert_text = str(body["alert_text"])
    else:
        alert_text = (
            f"RDP/SMB brute force: {count} failed Windows logons (EventCode 4625) "
            f"against user {user} on host {host} from external source IP {src_ip}. "
            f"Repeated failed authentication, credential access, remote service login."
        )

    return {
        "run_id": run_id,
        "timestamp": timestamp,
        "source": source,
        "search_name": body.get("search_name") or "",
        "results_link": body.get("results_link") or "",
        "console_link": body.get("console_link") or "",
        "src_ip": src_ip,
        "host": host,
        "user": user,
        "count": count,
        "enrich_ips": enrich_ips,
        "observed_iocs": {
            "ips": enrich_ips,
            "domains": [],
            "file_hashes": [],
            "users": [user],
            "hosts": [host],
        },
        "alert_text": alert_text,
    }
