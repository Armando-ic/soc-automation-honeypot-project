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


def _falcon_settings(tmp_path):
    return Settings(
        runs_path=str(tmp_path / "runs.jsonl"),
        state_path=str(tmp_path / "falcon-state.json"),
        falcon_pinned_aid="9134deadbeef5865",
        falcon_poll_cap=2,
    )


def test_falcon_state_default_empty(seeded_retriever, tmp_path):
    c = TestClient(create_app(seeded_retriever, _falcon_settings(tmp_path)))
    assert c.get("/falcon/state").json() == {"watermark": "", "seen": []}


def test_falcon_plan_dedups_and_caps(seeded_retriever, tmp_path):
    s = _falcon_settings(tmp_path)
    c = TestClient(create_app(seeded_retriever, s))
    # seed a seen-set via advance
    c.post("/falcon/advance", json={"results": [
        {"composite_id": "b", "created": "2026-06-29T00:00:00Z", "ok": True}]})
    r = c.post("/falcon/plan", json={"candidate_ids": ["a", "b", "c", "d"], "cap": None})
    assert r.json()["ids"] == ["a", "c"]          # b dropped (seen), cap=2 from settings


def test_falcon_map_route(seeded_retriever, tmp_path):
    c = TestClient(create_app(seeded_retriever, _falcon_settings(tmp_path)))
    r = c.post("/falcon/map", json={"alerts": [
        {"origin_cid": "cid", "id": "ind:aid:1-2-3", "created_timestamp": "2026-06-29T01:00:00Z",
         "severity_name": "High", "tactic": "Credential Access", "technique": "Brute Force",
         "technique_id": "T1110", "source_ips": ["203.0.113.10"], "user_name": "Administrator"}]})
    item = r.json()["items"][0]
    assert item["composite_id"] == "cid:ind:aid:1-2-3"          # reconstructed origin_cid:id
    assert item["created"] == "2026-06-29T01:00:00Z"            # created_timestamp
    assert item["body"]["result"]["src_ip"] == "203.0.113.10"  # from source_ips[]
    assert item["body"]["source"] == "falcon"


def test_falcon_map_route_sorts_oldest_first(seeded_retriever, tmp_path):
    # the route must re-sort by created (entities/alerts/v2 doesn't guarantee request order) so
    # advance_state's contiguous-prefix watermark can't strand an earlier alert (SKIP).
    c = TestClient(create_app(seeded_retriever, _falcon_settings(tmp_path)))

    def alert(cid, ts):
        return {"composite_id": cid, "created_timestamp": ts, "severity_name": "High",
                "tactic": "Credential Access", "technique": "Brute Force",
                "technique_id": "T1110", "source_ips": ["203.0.113.10"]}

    r = c.post("/falcon/map", json={"alerts": [
        alert("a:1", "2026-06-29T03:00:00Z"),
        alert("b:2", "2026-06-29T01:00:00Z"),
        alert("c:3", "2026-06-29T02:00:00Z")]})        # scrambled input
    items = r.json()["items"]
    assert [it["composite_id"] for it in items] == ["b:2", "c:3", "a:1"]
    assert [it["created"] for it in items] == [
        "2026-06-29T01:00:00Z", "2026-06-29T02:00:00Z", "2026-06-29T03:00:00Z"]


def test_falcon_advance_persists(seeded_retriever, tmp_path):
    s = _falcon_settings(tmp_path)
    c = TestClient(create_app(seeded_retriever, s))
    c.post("/falcon/advance", json={"results": [
        {"composite_id": "a", "created": "2026-06-29T02:00:00Z", "ok": True}]})
    assert c.get("/falcon/state").json() == {"watermark": "2026-06-29T02:00:00Z", "seen": ["a"]}


def test_falcon_contain_guard_ok_and_409(seeded_retriever, tmp_path):
    c = TestClient(create_app(seeded_retriever, _falcon_settings(tmp_path)))
    assert c.post("/falcon/contain-guard",
                  json={"resolved_ids": ["9134deadbeef5865"]}).json() == {"aid": "9134deadbeef5865"}
    bad = c.post("/falcon/contain-guard", json={"resolved_ids": ["wrong"]})
    assert bad.status_code == 409
