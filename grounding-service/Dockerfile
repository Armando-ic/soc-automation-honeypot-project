# Build context MUST be the repo root (so triage-verifier/ is COPYable). Build with:
#   docker build -f grounding-service/Dockerfile -t grounding-service:0.1 .
# (the compose file does this for you via build.context: ..)
FROM python:3.12-slim

# onnxruntime (pulled by fastembed) needs libgomp1 at runtime; curl is for smoke-tests/ops.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# All sibling packages the service lazy-imports at request time, layout preserved.
# triage-verifier is an editable-path dep of the service; malware-triage backs
# /deobfuscate + /triage-verdict; splunk-investigator backs /investigate. Omitting
# malware-triage or splunk-investigator makes those endpoints ImportError at request
# time and silently return an empty result (see tests/test_deploy_wiring.py).
COPY triage-verifier/ ./triage-verifier/
COPY malware-triage/ ./malware-triage/
COPY splunk-investigator/ ./splunk-investigator/
COPY grounding-service/ ./grounding-service/

# The verifier loads the deployed triage prompt from config.prompt_path
# (-> /app/JSON/honeypot-triage.json) EAGERLY at /verify time (verify_adapter.py ->
# TriageVerifier.from_paths). Without this file every /verify raises FileNotFoundError and
# fail-closes to verifier_error (shipped on the Task-17 first live run, runs 395/396/400).
COPY JSON/honeypot-triage.json ./JSON/honeypot-triage.json

# Verifier dep first, then the lazy-imported engines, then the service. splunk-investigator
# pulls in splunk-sdk (splunklib) via its own pyproject; no separate SDK install needed.
RUN pip install --no-cache-dir ./triage-verifier \
    && pip install --no-cache-dir ./malware-triage \
    && pip install --no-cache-dir ./splunk-investigator \
    && pip install --no-cache-dir ./grounding-service

# Bake the embedding model so the first /retrieve is fast and needs no network.
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5')"

# WORKDIR the service dir so `python scripts/ingest_attack.py` resolves (Task 6).
WORKDIR /app/grounding-service
EXPOSE 8000
CMD ["uvicorn", "grounding_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
