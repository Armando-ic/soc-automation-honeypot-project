"""Assemble the RAG grounding pack for a technique (spec section 3, step 1).

The target technique's description + tactics come from the committed grounding
pack (always offline, reviewable). The retriever supplies related-technique
NEIGHBORS from the live corpus for extra grounding. The allowed Sysmon field
vocabulary is fixed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from detection_authoring.config import load_config
from detection_authoring.sysmon_fields import ALLOWED_FIELDS


@dataclass
class GroundingPack:
    technique_id: str
    name: str
    tactics: list[str]
    description: str
    allowed_fields: list[str]
    neighbors: list[dict]


def build_grounding_pack(technique_id: str, retriever, grounding_dir: Path | None = None) -> GroundingPack:
    grounding_dir = grounding_dir or (load_config().corpus_dir / "grounding")
    path = grounding_dir / f"{technique_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"no grounding pack for {technique_id}: {path}")
    pack = json.loads(path.read_text(encoding="utf-8"))

    hits = retriever.search(pack.get("query_hint", pack["name"]), top_k=6)
    neighbors = [h for h in hits if h.get("id") != technique_id]

    return GroundingPack(
        technique_id=technique_id,
        name=pack["name"],
        tactics=pack["tactics"],
        description=pack["description"],
        allowed_fields=sorted(ALLOWED_FIELDS),
        neighbors=neighbors,
    )
