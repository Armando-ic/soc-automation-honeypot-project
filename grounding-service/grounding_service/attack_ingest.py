"""Parse MITRE enterprise-attack STIX into technique docs and upsert into Qdrant.

Parsing mirrors triage-verifier/scripts/regen_attack_reference.py (one source of
truth for how an attack-pattern maps to {id, name, tactics}).
"""
from __future__ import annotations

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from grounding_service.embedder import Embedder


def build_technique_docs(stix: dict) -> list[dict]:
    docs: list[dict] = []
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext:
            continue
        tid = ext["external_id"]
        name = obj.get("name", "")
        tactics = [
            ph["phase_name"]
            for ph in obj.get("kill_chain_phases", [])
            if ph.get("kill_chain_name") == "mitre-attack"
        ]
        desc = obj.get("description", "")
        text = f"{name}. {desc}".strip() if desc else name
        docs.append({"id": tid, "name": name, "tactics": tactics, "text": text})
    return docs


def ensure_collection(client: QdrantClient, name: str, dim: int) -> None:
    if not client.collection_exists(name):
        client.create_collection(
            name, vectors_config=VectorParams(size=dim, distance=Distance.COSINE)
        )


def upsert_techniques(
    client: QdrantClient, embedder: Embedder, name: str, docs: list[dict]
) -> int:
    vectors = embedder.embed([d["text"] for d in docs])
    points = [
        PointStruct(
            id=i,
            vector=vec,
            payload={"id": d["id"], "name": d["name"], "tactics": d["tactics"]},
        )
        for i, (d, vec) in enumerate(zip(docs, vectors))
    ]
    client.upsert(name, points=points)
    return len(points)
