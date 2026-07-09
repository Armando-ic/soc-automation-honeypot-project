import json
from fastapi.testclient import TestClient
from grounding_service.app import create_app
from grounding_service.config import Settings


def _client(seeded_retriever, tmp_path, factory=None):
    s = Settings(runs_path=str(tmp_path / "runs.jsonl"))
    return TestClient(create_app(seeded_retriever, s, deobf_client_factory=factory))


def test_deobfuscate_builtin_no_client(seeded_retriever, tmp_path):
    c = _client(seeded_retriever, tmp_path, factory=None)
    r = c.post("/deobfuscate", json={"payload": "powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgAA=="})
    body = r.json()
    assert r.status_code == 200
    assert body["final_plaintext"] == "Write-Host "
    assert body["verdict_inputs"]["fully_resolved"] is True


def test_deobfuscate_survives_client_outage(seeded_retriever, tmp_path):
    def boom():
        raise RuntimeError("no key")
    c = _client(seeded_retriever, tmp_path, factory=boom)
    r = c.post("/deobfuscate", json={"payload": "powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgAA=="})
    assert r.status_code == 200 and r.json()["final_plaintext"] == "Write-Host "


def test_triage_verdict_is_pure(seeded_retriever, tmp_path):
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/triage-verdict", json={
        "behavioral_hits": [{"rule_id": "exec.iex", "category": "exec", "evidence": "IEX"}],
        "ioc_verdicts": {"http://x": "malicious"},
        "fully_resolved": True, "flags": []})
    assert r.json()["verdict"] == "malicious"
