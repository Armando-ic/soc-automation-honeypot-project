# Build context MUST be the repo root (so triage-verifier/ is COPYable). Build with:
#   docker build -f grounding-service/Dockerfile -t grounding-service:0.1 .
# (the compose file does this for you via build.context: ..)
FROM python:3.12-slim

# onnxruntime (pulled by fastembed) needs libgomp1 at runtime; curl is for smoke-tests/ops.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Both packages, sibling layout preserved (triage-verifier is an editable-path dep of the service).
COPY triage-verifier/ ./triage-verifier/
COPY grounding-service/ ./grounding-service/

# Verifier dep first, then the service.
RUN pip install --no-cache-dir ./triage-verifier \
    && pip install --no-cache-dir ./grounding-service

# Bake the embedding model so the first /retrieve is fast and needs no network.
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5')"

# WORKDIR the service dir so `python scripts/ingest_attack.py` resolves (Task 6).
WORKDIR /app/grounding-service
EXPOSE 8000
CMD ["uvicorn", "grounding_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
