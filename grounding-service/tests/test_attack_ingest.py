import json
from pathlib import Path

from qdrant_client import QdrantClient

from grounding_service.attack_ingest import (
    build_technique_docs,
    ensure_collection,
    upsert_techniques,
)
from grounding_service.embedder import FakeEmbedder

STIX = Path(__file__).resolve().parent / "fixtures" / "mini_attack_stix.json"


def _stix() -> dict:
    return json.loads(STIX.read_text(encoding="utf-8"))


def test_build_docs_skips_deprecated_and_maps_fields():
    docs = build_technique_docs(_stix())
    ids = {d["id"] for d in docs}
    assert ids == {"T1110", "T1059.001", "T1021.001"}  # T9999 deprecated -> skipped
    t1110 = next(d for d in docs if d["id"] == "T1110")
    assert t1110["name"] == "Brute Force"
    assert t1110["tactics"] == ["credential-access"]
    assert "brute force" in t1110["text"].lower()


def test_upsert_then_count():
    client = QdrantClient(":memory:")
    emb = FakeEmbedder(dim=8)
    docs = build_technique_docs(_stix())
    ensure_collection(client, "attack_techniques", emb.dim)
    n = upsert_techniques(client, emb, "attack_techniques", docs)
    assert n == 3
    assert client.count("attack_techniques").count == 3


def test_ensure_collection_idempotent():
    client = QdrantClient(":memory:")
    emb = FakeEmbedder(dim=8)
    ensure_collection(client, "attack_techniques", emb.dim)
    ensure_collection(client, "attack_techniques", emb.dim)  # second call must not raise
