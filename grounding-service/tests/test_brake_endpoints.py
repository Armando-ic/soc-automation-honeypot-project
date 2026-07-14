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
