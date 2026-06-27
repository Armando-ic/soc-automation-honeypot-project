"""Populate Qdrant with the MITRE ATT&CK technique corpus.

Usage:
  python scripts/ingest_attack.py                 # download enterprise-attack STIX
  python scripts/ingest_attack.py path/to/stix.json
"""
from __future__ import annotations

import json
import sys
import urllib.request

from qdrant_client import QdrantClient

from grounding_service.attack_ingest import (
    build_technique_docs,
    ensure_collection,
    upsert_techniques,
)
from grounding_service.config import load_settings
from grounding_service.embedder import BgeEmbedder

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _load_stix(arg: str | None) -> dict:
    if arg:
        return json.loads(open(arg, encoding="utf-8").read())
    with urllib.request.urlopen(STIX_URL) as resp:  # noqa: S310 (official MITRE source)
        return json.load(resp)


def main() -> None:
    settings = load_settings()
    stix = _load_stix(sys.argv[1] if len(sys.argv) > 1 else None)
    docs = build_technique_docs(stix)
    client = QdrantClient(url=settings.qdrant_url)
    embedder = BgeEmbedder(settings.embed_model)
    ensure_collection(client, settings.collection, embedder.dim)
    n = upsert_techniques(client, embedder, settings.collection, docs)
    print(f"ingested {n} techniques into {settings.collection}")


if __name__ == "__main__":
    main()
