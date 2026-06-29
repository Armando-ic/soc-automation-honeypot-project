"""Service settings, read from env with safe defaults (no pydantic-settings dep)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_VERIFIER = _REPO_ROOT / "triage-verifier"


@dataclass(frozen=True)
class Settings:
    qdrant_url: str = os.getenv("QDRANT_URL", "http://127.0.0.1:6333")
    collection: str = os.getenv("ATTACK_COLLECTION", "attack_techniques")
    embed_model: str = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
    top_k_default: int = int(os.getenv("RETRIEVE_TOP_K", "6"))
    model: str = os.getenv("TRIAGE_MODEL", "claude-opus-4-8")
    runs_path: str = os.getenv("RUNS_PATH", str(Path.cwd() / "runs.jsonl"))
    schema_path: str = os.getenv(
        "VERIFIER_SCHEMA", str(_VERIFIER / "schema" / "submit_triage_result.json")
    )
    attack_ref_path: str = os.getenv(
        "ATTACK_REF", str(_VERIFIER / "data" / "attack_reference.json")
    )
    state_path: str = os.getenv(
        "FALCON_STATE_PATH", str(Path.cwd() / "falcon-poller-state.json")
    )
    falcon_pinned_aid: str = os.getenv("FALCON_PINNED_AID", "")
    falcon_poll_cap: int = int(os.getenv("FALCON_POLL_CAP", "8"))


def load_settings() -> Settings:
    return Settings()
