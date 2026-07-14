# grounding-service/tests/test_brake_endpoints.py
from fastapi.testclient import TestClient

from grounding_service.app import create_app
from grounding_service.config import Settings


class _StubRetriever:
    def search(self, text, top_k):
        return []


def _client(**env):
    settings = Settings(**env) if env else Settings()
    return TestClient(create_app(_StubRetriever(), settings))


def test_evaluate_quiet_no_trip():
    c = _client(splunk_host_ip="20.1.2.3")
    r = c.post("/brake/evaluate", json={
        "events": [{"dst_ip": "93.184.0.1", "dst_port": 443}], "source": "splunk"})
    assert r.status_code == 200
    body = r.json()
    assert body["trip"] is False and body["source"] == "splunk"


def test_evaluate_fanout_trips():
    c = _client(splunk_host_ip="20.1.2.3", brake_distinct_dst_max=5)
    events = [{"dst_ip": f"93.184.{i}.{i}", "dst_port": 443} for i in range(10)]
    r = c.post("/brake/evaluate", json={"events": events, "source": "nsg"})
    assert r.json()["trip"] is True and r.json()["reason"] == "egress_fanout"


class _FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._p = payload or {}

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("boom")


class _FakeSession:
    def post(self, url, data=None, timeout=None):
        return _FakeResp(payload={"access_token": "tok"})

    def put(self, url, json=None, headers=None, timeout=None):
        return _FakeResp(payload={"properties": {"provisioningState": "Succeeded", "access": "Deny"}})

    def get(self, url, headers=None, timeout=None):
        return _FakeResp(payload={"properties": {"provisioningState": "Succeeded", "access": "Deny"}})


_CREDS = dict(brake_enabled=True, azure_tenant_id="t", azure_client_id="c",
              azure_client_secret="x", honeypot_subscription_id="sub",
              honeypot_nsg_rg="rg", honeypot_nsg_name="nsg")


def _client_with_factory(factory, **env):
    from grounding_service.app import create_app
    from grounding_service.config import Settings
    return TestClient(create_app(_StubRetriever(), Settings(**env),
                                 azure_brake_session_factory=factory))


def test_nsg_deny_inert_when_disabled():
    c = _client_with_factory(lambda: _FakeSession())  # brake_enabled defaults False
    r = c.post("/brake/nsg-deny", json={})
    assert r.json() == {"fired": False, "reason": "brake_not_configured",
                        "access": "", "provisioning_state": ""}


def test_nsg_deny_inert_when_creds_missing():
    c = _client_with_factory(lambda: _FakeSession(), brake_enabled=True)  # no creds
    assert c.post("/brake/nsg-deny", json={}).json()["reason"] == "brake_not_configured"


def test_nsg_deny_fires_when_enabled_and_configured():
    c = _client_with_factory(lambda: _FakeSession(), **_CREDS)
    body = c.post("/brake/nsg-deny", json={}).json()
    assert body["fired"] is True and body["access"] == "Deny"


def test_nsg_deny_never_raises_on_azure_error():
    class _BoomSession(_FakeSession):
        def put(self, url, json=None, headers=None, timeout=None):
            return _FakeResp(status_code=500)
    c = _client_with_factory(lambda: _BoomSession(), **_CREDS)
    body = c.post("/brake/nsg-deny", json={}).json()
    assert body["fired"] is False and body["reason"] == "brake_error"
