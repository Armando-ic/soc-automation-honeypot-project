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


_MGMT = "https://management.azure.com"
_LOGIN = "https://login.microsoftonline.com"


def fetch_token(session, *, tenant, client_id, client_secret, timeout=30) -> str:
    url = f"{_LOGIN}/{tenant}/oauth2/v2.0/token"
    resp = session.post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"{_MGMT}/.default",
    }, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["access_token"]


def _rule_url(subscription, resource_group, nsg, rule_name, api_version):
    return (f"{_MGMT}/subscriptions/{subscription}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Network/networkSecurityGroups/{nsg}"
            f"/securityRules/{rule_name}?api-version={api_version}")


def nsg_deny_egress(session, token, *, subscription, resource_group, nsg, rule_name,
                    priority, api_version="2023-09-01", timeout=30) -> dict:
    """PUT a deny-all Outbound rule at a high-precedence priority, then read it back."""
    url = _rule_url(subscription, resource_group, nsg, rule_name, api_version)
    body = {"properties": {
        "protocol": "*", "access": "Deny", "direction": "Outbound", "priority": int(priority),
        "sourceAddressPrefix": "*", "sourcePortRange": "*",
        "destinationAddressPrefix": "*", "destinationPortRange": "*",
        "description": "honeypot-opening auto-brake egress deny",
    }}
    resp = session.put(url, json=body, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    resp.raise_for_status()
    props = (resp.json() or {}).get("properties", {})
    return {"status_code": resp.status_code,
            "provisioning_state": props.get("provisioningState", ""),
            "access": props.get("access", "")}


def nsg_rule_status(session, token, *, subscription, resource_group, nsg, rule_name,
                    api_version="2023-09-01", timeout=30) -> dict:
    url = _rule_url(subscription, resource_group, nsg, rule_name, api_version)
    resp = session.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    resp.raise_for_status()
    props = (resp.json() or {}).get("properties", {})
    return {"access": props.get("access", ""), "provisioning_state": props.get("provisioningState", "")}
