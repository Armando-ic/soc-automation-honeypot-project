"""Settings, read from env with safe defaults (mirrors grounding-service)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent  # detection-authoring/


@dataclass(frozen=True)
class Config:
    qdrant_url: str = os.getenv("QDRANT_URL", "http://127.0.0.1:6333")
    collection: str = os.getenv("ATTACK_COLLECTION", "attack_techniques")
    embed_model: str = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
    model: str = os.getenv("AUTHORING_MODEL", "claude-opus-4-8")
    max_tokens: int = int(os.getenv("AUTHORING_MAX_TOKENS", "4096"))
    corpus_dir: Path = _PKG_ROOT / "corpus"
    rules_dir: Path = _PKG_ROOT / "rules"
    reports_dir: Path = _PKG_ROOT / "reports"


def load_config() -> Config:
    return Config()
