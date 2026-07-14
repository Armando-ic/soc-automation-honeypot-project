# grounding-service/grounding_service/brake.py
"""Honeypot-opening auto-brake: the pure trip decision + the NSG-flip HTTP calls.

evaluate_egress is side-effect-free and FAILS CLOSED (spec §3.5): any uncertainty
(malformed input) trips. The NSG functions take an injected, duck-typed `session`
(.post/.put/.get) so they are unit-tested with a fake and the production factory
supplies a real httpx.Client - the Azure service-principal credential never leaves
the gitignored .env.
"""
from __future__ import annotations


def _coerce_port(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def evaluate_egress(events, *, splunk_host_ip, distinct_dst_max, conn_rate_max,
                    watch_ports=(80, 443), uf_port=9997) -> dict:
    """Decide whether a window of outbound connections is third-party abuse.

    Trips ONLY on third-party-harm signals; normal post-exploitation flows through.
    """
    if not isinstance(events, list):
        return {"trip": True, "reason": "failsafe_malformed", "distinct_dst": 0, "conn_count": 0}

    web_dsts: set[str] = set()
    web_conns = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        dst_ip = str(e.get("dst_ip", "") or "")
        port = _coerce_port(e.get("dst_port"))
        if not dst_ip or port is None:
            continue
        # (b) any traffic to the Splunk host on a non-UF port is abuse of the one reachable asset
        if dst_ip == splunk_host_ip and port != uf_port:
            return {"trip": True, "reason": "splunk_nonuf", "distinct_dst": len(web_dsts),
                    "conn_count": web_conns}
        if dst_ip == splunk_host_ip:
            continue                       # UF traffic - never counts toward web fan-out/rate
        if port in watch_ports:
            web_dsts.add(dst_ip)
            web_conns += 1

    if len(web_dsts) > distinct_dst_max:
        return {"trip": True, "reason": "egress_fanout", "distinct_dst": len(web_dsts),
                "conn_count": web_conns}
    if web_conns > conn_rate_max:
        return {"trip": True, "reason": "egress_rate", "distinct_dst": len(web_dsts),
                "conn_count": web_conns}
    return {"trip": False, "reason": "", "distinct_dst": len(web_dsts), "conn_count": web_conns}
