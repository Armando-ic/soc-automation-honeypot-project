# grounding-service/tests/test_brake_e2e.py
from fastapi.testclient import TestClient

from grounding_service.app import create_app
from grounding_service.config import Settings


class _StubRetriever:
    def search(self, text, top_k):
        return []


class _Resp:
    def __init__(self, payload):
        self.status_code = 200
        self._p = payload

    def json(self):
        return self._p

    def raise_for_status(self):
        return None


class _Session:
    def post(self, url, data=None, timeout=None):
        return _Resp({"access_token": "tok"})

    def put(self, url, json=None, headers=None, timeout=None):
        return _Resp({"properties": {"provisioningState": "Succeeded", "access": "Deny"}})

    def get(self, url, headers=None, timeout=None):
        return _Resp({"properties": {"provisioningState": "Succeeded", "access": "Deny"}})


def test_fanout_evaluates_to_trip_then_nsg_deny_fires():
    settings = Settings(brake_enabled=True, splunk_host_ip="20.1.2.3",
                        brake_distinct_dst_max=5, azure_tenant_id="t",
                        azure_client_id="c", azure_client_secret="x",
                        honeypot_subscription_id="s", honeypot_nsg_rg="rg",
                        honeypot_nsg_name="nsg")
    c = TestClient(create_app(_StubRetriever(), settings,
                              azure_brake_session_factory=lambda: _Session()))
    events = [{"dst_ip": f"93.184.{i}.{i}", "dst_port": 443} for i in range(10)]
    ev = c.post("/brake/evaluate", json={"events": events, "source": "nsg"}).json()
    assert ev["trip"] is True
    fired = c.post("/brake/nsg-deny", json={}).json()
    assert fired["fired"] is True and fired["access"] == "Deny"
