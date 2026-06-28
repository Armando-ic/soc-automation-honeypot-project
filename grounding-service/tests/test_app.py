import pytest
from fastapi.testclient import TestClient

from grounding_service.app import create_app
from grounding_service.config import Settings

GOOD = {
    "schema_version": "v1", "alert_summary": "x", "severity": "low", "severity_rationale": "x",
    "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "credential-access"}],
    "iocs": {"ips": ["203.0.113.10"], "domains": [], "file_hashes": [], "users": [], "hosts": []},
    "iocs_enriched": [{"value": "203.0.113.10", "ioc_type": "ip", "verdict": "malicious",
                       "source": "abuseipdb", "summary": "x"}],
    "recommended_actions": [{"description": "block", "priority": "high"}],
    "investigation_notes": "x",
}


@pytest.fixture
def client(seeded_retriever, tmp_path):  # seeded_retriever comes from conftest.py
    settings = Settings(runs_path=str(tmp_path / "runs.jsonl"))
    return TestClient(create_app(seeded_retriever, settings))


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_retrieve(client):
    body = client.post("/retrieve", json={"alert_text": "brute force", "top_k": 3}).json()
    assert body["ids"][0] == "T1110"
    assert body["techniques"][0]["name"] == "Brute Force"


def test_normalize(client):
    r = client.post("/normalize", json={"items": [
        {"ioc": "1.2.3.4", "provider": "abuseipdb", "response": {"data": {"abuseConfidenceScore": 100}}},
    ]})
    assert r.json() == {"enrichment_results": {"1.2.3.4": "malicious"}}


def test_verify(client):
    r = client.post("/verify", json={
        "result": GOOD, "retrieved": ["T1110"],
        "enrichment_results": {"203.0.113.10": "malicious"},
        "run_meta": {"run_id": "r1", "timestamp": "t", "tokens_in": 1, "tokens_out": 1, "latency_ms": 1},
    })
    assert r.json()["verification_passed"] is True


def test_verify_returns_200_not_500_on_verifier_crash(seeded_retriever, tmp_path, monkeypatch):
    from grounding_service import verify_adapter

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(verify_adapter.TriageVerifier, "from_paths", boom)
    settings = Settings(runs_path=str(tmp_path / "runs.jsonl"))
    c = TestClient(create_app(seeded_retriever, settings))
    r = c.post("/verify", json={
        "result": GOOD, "retrieved": ["T1110"],
        "enrichment_results": {"203.0.113.10": "malicious"},
        "run_meta": {"run_id": "r1", "timestamp": "t", "tokens_in": 1, "tokens_out": 1, "latency_ms": 1},
    })
    assert r.status_code == 200
    assert r.json()["verification_passed"] is False
