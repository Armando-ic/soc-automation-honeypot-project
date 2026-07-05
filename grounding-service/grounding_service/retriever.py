"""Cosine retrieval over the Qdrant ATT&CK collection."""
from __future__ import annotations

from qdrant_client import QdrantClient

from grounding_service.embedder import Embedder
from grounding_service.rerank import collapse_to_parents, select_with_tactic_diversity

OVERFETCH = 24  # candidate pool size before the diversity narrow-down


class AttackRetriever:
    def __init__(self, client: QdrantClient, embedder: Embedder, collection: str) -> None:
        self._client = client
        self._embedder = embedder
        self._collection = collection
        self._by_id_cache: dict[str, dict] | None = None

    def _by_id(self) -> dict[str, dict]:
        """Lazily build + cache an id -> {name, tactics} map of the whole
        collection (one Qdrant scroll), so a retrieved sub-technique can be
        rolled up to its parent's real payload (Plan 2, A3). Empty when the
        collection is empty/unreachable, which makes the roll-up a no-op."""
        if self._by_id_cache is None:
            by_id: dict[str, dict] = {}
            offset = None
            while True:
                points, offset = self._client.scroll(
                    collection_name=self._collection,
                    limit=256,
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )
                for p in points:
                    payload = p.payload or {}
                    tid = payload.get("id", "")
                    if tid:
                        by_id[tid] = {
                            "name": payload.get("name", ""),
                            "tactics": payload.get("tactics", []),
                        }
                if offset is None:
                    break
            self._by_id_cache = by_id
        return self._by_id_cache

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
        # Roll retrieved sub-techniques up to their PARENT technique so the hot
        # parent id the scorer checks surfaces (Plan 2, A3), then narrow to top_k.
        pool = collapse_to_parents(pool, self._by_id())
        return select_with_tactic_diversity(pool, top_k)

    def retrieved_ids(self, alert_text: str, top_k: int = 6) -> list[str]:
        return [h["id"] for h in self.search(alert_text, top_k)]
