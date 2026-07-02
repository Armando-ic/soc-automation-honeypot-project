"""Reuse the real grounding-service retriever so the harness retrieves ATT&CK
techniques exactly as the deployed n8n `retrieve` node does.

`build_local_retriever` is the LIVE path: a real Qdrant instance + BgeEmbedder
against the `attack_techniques` collection (seeded via
`grounding-service/scripts/ingest_attack.py`, Task 15). It is not exercised by
the offline unit tests in this package — those use an in-memory
`seeded_retriever` fixture (`QdrantClient(":memory:")` + `FakeEmbedder`).
"""
from __future__ import annotations

from grounding_service.embedder import BgeEmbedder
from grounding_service.retriever import AttackRetriever
from qdrant_client import QdrantClient

# The deployed n8n `retrieve` node posts top_k: 8 (build_honeypot_triage_workflow.py:389),
# NOT the grounding-service library default of 6. Both the candidate menu handed to
# Opus and the mitre_in_retrieved allow-list handed to the verifier depend on this
# size, so the harness pins 8 here rather than inheriting the library default —
# do not let this silently drift back to 6.
DEFAULT_TOP_K = 8


def build_local_retriever(
    qdrant_url: str | None = None, collection: str = "attack_techniques"
) -> AttackRetriever:
    """Build a retriever against a real, locally-running Qdrant instance."""
    client = QdrantClient(url=qdrant_url or "http://127.0.0.1:6333", check_compatibility=False)
    embedder = BgeEmbedder()
    return AttackRetriever(client, embedder, collection)


def retrieve(retriever: AttackRetriever, alert_text: str, top_k: int = DEFAULT_TOP_K) -> tuple[list[dict], list[str]]:
    """Search for the top_k closest ATT&CK techniques to alert_text.

    Returns (techniques, ids) where techniques is the list of
    {id, name, tactics, score} dicts and ids is the parallel list of technique ids.
    """
    techniques = retriever.search(alert_text, top_k)
    ids = [t["id"] for t in techniques]
    return techniques, ids


def assert_pinned_subset(pinned: list[str], real_ids: list[str]) -> None:
    """Guard against fixture/scenario drift: every pinned technique id must
    actually exist in the real retrieved ids, or the scenario is testing
    against a technique that doesn't exist in this retrieval result."""
    missing = [p for p in pinned if p not in real_ids]
    assert not missing, f"pinned technique id(s) not found in real_ids: {missing}"
