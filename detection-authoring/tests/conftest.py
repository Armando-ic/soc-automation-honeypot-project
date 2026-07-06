import json
from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from grounding_service.attack_ingest import (
    build_technique_docs,
    ensure_collection,
    upsert_techniques,
)
from grounding_service.embedder import FakeEmbedder
from grounding_service.retriever import AttackRetriever

ROOT = Path(__file__).resolve().parent
STIX = ROOT / "fixtures" / "mini_attack_stix.json"


@pytest.fixture
def seeded_retriever():
    client = QdrantClient(":memory:")
    emb = FakeEmbedder(dim=8)
    docs = build_technique_docs(json.loads(STIX.read_text(encoding="utf-8")))
    for d in docs:
        d["text"] = d["name"].lower()
    ensure_collection(client, "attack_techniques", emb.dim)
    upsert_techniques(client, emb, "attack_techniques", docs)
    return AttackRetriever(client, emb, "attack_techniques")
