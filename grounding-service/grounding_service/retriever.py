"""Cosine retrieval over the Qdrant ATT&CK collection."""
from __future__ import annotations

from qdrant_client import QdrantClient

from grounding_service.embedder import Embedder
from grounding_service.rerank import select_with_tactic_diversity

OVERFETCH = 24  # candidate pool size before the diversity narrow-down


class AttackRetriever:
    def __init__(self, client: QdrantClient, embedder: Embedder, collection: str) -> None:
        self._client = client
        self._embedder = embedder
        self._collection = collection

    def search(self, alert_text: str, top_k: int = 6) -> list[dict]:
        vector = self._embedder.embed([alert_text])[0]
        # Plan 0D-1a brief specifies client.search(...) but qdrant-client >=1.14
        # removed .search() entirely (AttributeError, not DeprecationWarning).
        # Using query_points(...).points — the direct functional replacement.
        # Over-fetch a wider pool, then narrow to top_k with a tactic-diversity
        # rerank so a starved high-value tactic (Plan 2, A3) still surfaces.
        response = self._client.query_points(
            collection_name=self._collection, query=vector, limit=max(top_k, OVERFETCH)
        )
        hits = response.points
        pool: list[dict] = []
        for h in hits:
            payload = h.payload or {}
            pool.append(
                {
                    "id": payload.get("id", ""),
                    "name": payload.get("name", ""),
                    "tactics": payload.get("tactics", []),
                    "score": float(h.score),
                }
            )
        return select_with_tactic_diversity(pool, top_k)

    def retrieved_ids(self, alert_text: str, top_k: int = 6) -> list[str]:
        return [h["id"] for h in self.search(alert_text, top_k)]
