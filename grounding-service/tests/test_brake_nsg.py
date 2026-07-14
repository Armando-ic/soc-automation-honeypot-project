# grounding-service/tests/test_brake_nsg.py
import pytest

from grounding_service.brake import fetch_token, nsg_deny_egress, nsg_rule_status


class FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, token_resp=None, put_resp=None, get_resp=None):
        self.calls = []
        self._token = token_resp or FakeResp(payload={"access_token": "tok-123"})
        self._put = put_resp or FakeResp(
            payload={"properties": {"provisioningState": "Succeeded", "access": "Deny"}})
        self._get = get_resp or FakeResp(
            payload={"properties": {"provisioningState": "Succeeded", "access": "Deny"}})

    def post(self, url, data=None, timeout=None):
        self.calls.append(("post", url, data))
        return self._token

    def put(self, url, json=None, headers=None, timeout=None):
        self.calls.append(("put", url, json, headers))
        return self._put

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("get", url, headers))
        return self._get


RG = dict(subscription="sub-1", resource_group="rg-honeypot", nsg="nsg-honeypot",
          rule_name="honeypot-brake-egress-deny")


def test_fetch_token_returns_access_token():
    s = FakeSession()
    tok = fetch_token(s, tenant="t", client_id="c", client_secret="x")
    assert tok == "tok-123"
    assert s.calls[0][0] == "post" and "login.microsoftonline.com" in s.calls[0][1]


def test_nsg_deny_puts_a_deny_outbound_rule_and_reads_back():
    s = FakeSession()
    out = nsg_deny_egress(s, "tok-123", priority=100, **RG)
    assert out["access"] == "Deny" and out["provisioning_state"] == "Succeeded"
    put = [c for c in s.calls if c[0] == "put"][0]
    body = put[2]["properties"]
    assert body["access"] == "Deny"
    assert body["direction"] == "Outbound"
    assert body["priority"] == 100
    assert "securityRules/honeypot-brake-egress-deny" in put[1]
    assert put[3]["Authorization"] == "Bearer tok-123"


def test_nsg_deny_raises_on_http_error():
    s = FakeSession(put_resp=FakeResp(status_code=403))
    with pytest.raises(RuntimeError):
        nsg_deny_egress(s, "tok", priority=100, **RG)


def test_nsg_rule_status_reads_access():
    s = FakeSession()
    out = nsg_rule_status(s, "tok", **RG)
    assert out["access"] == "Deny" and out["provisioning_state"] == "Succeeded"
