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

ROOT = Path(__file__).resolve().parent.parent          # red-team/
REPO = ROOT.parent                                      # repo root
SNAP = ROOT / "snapshots"
WORKFLOW_JSON = REPO / "JSON" / "honeypot-triage.json"
STIX = ROOT / "tests" / "fixtures" / "mini_attack_stix.json"


def load_snapshot(name: str) -> dict:
    return json.loads((SNAP / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def seeded_retriever():
    client = QdrantClient(":memory:")
    emb = FakeEmbedder(dim=8)
    docs = build_technique_docs(json.loads(STIX.read_text(encoding="utf-8")))
    # Make the doc text equal to a query string so FakeEmbedder gives an exact
    # cosine match for that query (tests the plumbing deterministically; real
    # semantic quality is validated manually with BgeEmbedder — see README).
    for d in docs:
        d["text"] = d["name"].lower()
    ensure_collection(client, "attack_techniques", emb.dim)
    upsert_techniques(client, emb, "attack_techniques", docs)
    return AttackRetriever(client, emb, "attack_techniques")
