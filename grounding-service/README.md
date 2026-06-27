# grounding-service (honeypot Phase 0D-1a)

MITRE ATT&CK retrieval + `triage-verifier` gate for the honeypot SOAR. A FastAPI app the n8n
workflow (Plan 0D-1b) calls. Co-located on the n8n VM; n8n reaches it over loopback.

## Endpoints
- `POST /retrieve` `{alert_text, top_k?}` → `{techniques:[{id,name,tactics,score}], ids:[...]}` — the `ids` are the verifier's `retrieved` set; the techniques ground the Opus prompt.
- `POST /normalize` `{items:[{ioc,provider,response}]}` → `{enrichment_results:{ioc:verdict}}` — provider responses → verdicts.
- `POST /verify` `{result, retrieved, enrichment_results, run_meta}` → run-record (carries `verification_passed`, `check_results`, `provenance`); appends one `runs.jsonl` line. n8n gates on `verification_passed`.
- `GET /health` → `{status:"ok"}`.

## Run (dev)
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e "../triage-verifier"
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest tests/ -v          # fully offline (FakeEmbedder, in-memory Qdrant, mocked judge)
```

## Deploy (prod, on the n8n VM)
```bash
docker run -d -p 127.0.0.1:6333:6333 -v $PWD/qdrant_storage:/qdrant/storage qdrant/qdrant
.venv/bin/python scripts/ingest_attack.py         # populate the ATT&CK collection
ANTHROPIC_API_KEY=... .venv/bin/uvicorn grounding_service.main:app --host 127.0.0.1 --port 8000
```

## Honest limitations
- Retrieval quality depends on bge-small + the ATT&CK corpus; tune `top_k` against real alerts. Unit tests use a FakeEmbedder (exact-match plumbing only) — semantic quality is a manual check.
- Enrichment verdict thresholds (`enrichment.py`) are pinned starting values (design spec §10) — tune against real provider data.
- The `ClaudeJudge` is advisory and **never auto-approves**; on a missing key or judge error the service falls back to `StubJudge` (`needs_human`). Its notes embed untrusted model output — treat as display text only.
- Qdrant must bind to localhost only; the service port is reachable only from the n8n host.
