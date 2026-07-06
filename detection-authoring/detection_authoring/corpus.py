"""Load the frozen event corpus (spec section 5)."""
from __future__ import annotations

import json

from detection_authoring.config import load_config


def load_positives(technique_id: str) -> list[dict]:
    path = load_config().corpus_dir / "positives" / f"{technique_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"no frozen positive corpus for {technique_id}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_benign() -> list[dict]:
    path = load_config().corpus_dir / "benign" / "baseline.json"
    return json.loads(path.read_text(encoding="utf-8"))
