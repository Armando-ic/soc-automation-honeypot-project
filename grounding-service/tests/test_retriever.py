from qdrant_client import QdrantClient

from grounding_service.attack_ingest import ensure_collection, upsert_techniques
from grounding_service.embedder import FakeEmbedder
from grounding_service.retriever import AttackRetriever


def test_search_returns_ranked_payloads(seeded_retriever):
    hits = seeded_retriever.search("brute force", top_k=3)
    assert hits[0]["id"] == "T1110"
    assert hits[0]["name"] == "Brute Force"
    assert hits[0]["tactics"] == ["credential-access"]
    assert hits[0]["score"] >= hits[-1]["score"]


def test_retrieved_ids_is_id_list(seeded_retriever):
    ids = seeded_retriever.retrieved_ids("powershell", top_k=3)
    assert ids[0] == "T1059.001"
    assert all(isinstance(i, str) for i in ids)


def test_search_still_returns_top_k_length(seeded_retriever):
    hits = seeded_retriever.search("brute force", top_k=3)
    assert len(hits) == 3
    assert hits[0]["id"] == "T1110"              # top hit preserved through rerank
    assert hits[0]["score"] >= hits[-1]["score"]


def test_search_overfetches_more_than_top_k(monkeypatch, seeded_retriever):
    # Assert the Qdrant query is issued with an over-fetch limit > top_k so the
    # rerank has a pool to promote a starved tactic from.
    seen = {}
    real = seeded_retriever._client.query_points

    def spy(*args, **kwargs):
        seen["limit"] = kwargs.get("limit")
        return real(*args, **kwargs)

    monkeypatch.setattr(seeded_retriever._client, "query_points", spy)
    seeded_retriever.search("brute force", top_k=3)
    assert seen["limit"] is not None and seen["limit"] > 3


def _rollup_retriever():
    # A tiny corpus that contains BOTH a parent and its sub, so the roll-up
    # actually fires (the shared mini-STIX fixture has no such pair).
    client = QdrantClient(":memory:")
    emb = FakeEmbedder(dim=8)
    docs = [
        {"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "text": "brute force"},
        {"id": "T1110.001", "name": "Password Guessing", "tactics": ["credential-access"], "text": "password guessing"},
        {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"], "text": "os credential dumping"},
        {"id": "T1003.006", "name": "DCSync", "tactics": ["credential-access"], "text": "dcsync"},
    ]
    ensure_collection(client, "attack_techniques", emb.dim)
    upsert_techniques(client, emb, "attack_techniques", docs)
    return AttackRetriever(client, emb, "attack_techniques")


def test_search_rolls_retrieved_sub_up_to_parent_id():
    r = _rollup_retriever()
    ids = r.retrieved_ids("password guessing", top_k=8)  # exact-matches the T1110.001 doc
    assert "T1110" in ids            # the parent surfaced from its retrieved sub
    assert "T1110.001" not in ids    # the sub id was rolled up, not left as-is
