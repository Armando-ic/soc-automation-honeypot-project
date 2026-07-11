"""Production wiring: real Qdrant + bge-small + Anthropic-key judge factory.

Run:  uvicorn grounding_service.main:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import os

from qdrant_client import QdrantClient

from grounding_service.app import create_app
from grounding_service.config import Settings, load_settings
from grounding_service.embedder import BgeEmbedder
from grounding_service.retriever import AttackRetriever


def _build_retriever(settings: Settings) -> AttackRetriever:
    client = QdrantClient(url=settings.qdrant_url, check_compatibility=False)
    return AttackRetriever(client, BgeEmbedder(settings.embed_model), settings.collection)


def _judge_client_factory() -> object:
    import anthropic

    return anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


def build_default_app():
    settings = load_settings()
    retriever = _build_retriever(settings)
    # Same Anthropic client builder feeds BOTH the judge (verify path) and the deobf
    # proposal (/deobfuscate). Without wiring deobf_client_factory the deployed endpoint
    # runs decode_and_verify(client=None) and the model-in-the-loop decode is silently
    # dead. Gated on the key so a keyless deploy degrades to builtins and never blocks.
    factory = _judge_client_factory if os.getenv("ANTHROPIC_API_KEY") else None
    return create_app(retriever, settings,
                      judge_client_factory=factory,
                      deobf_client_factory=factory)


app = build_default_app()
