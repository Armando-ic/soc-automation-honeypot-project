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

    # timeout=60.0 mirrors the CLI live branch (scripts/run_investigation.py) and bounds
    # every call the shared factory serves -- especially the up-to-MAX_TURNS /investigate
    # loop, where a hung response would otherwise tie up a worker for the SDK default (~600s).
    return anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=60.0)


def _splunk_service_factory() -> object:
    """Build a read-only splunklib Service from SPLUNK_* env (mirrors the CLI's
    scripts/run_investigation.py live branch). Only reached when SPLUNK_HOST and
    SPLUNK_PASSWORD are set (see build_default_app); a connect failure is caught by the
    /investigate handler and degrades to splunk_outage, never a crash."""
    import splunklib.client as splunklib_client

    return splunklib_client.connect(
        host=os.environ["SPLUNK_HOST"],
        port=int(os.environ.get("SPLUNK_PORT", "8089")),
        username=os.environ["SPLUNK_USERNAME"],
        password=os.environ["SPLUNK_PASSWORD"],
        scheme=os.environ.get("SPLUNK_SCHEME", "https"),
    )


def build_default_app():
    settings = load_settings()
    retriever = _build_retriever(settings)
    # Same Anthropic client builder feeds the judge (verify path), the deobf proposal
    # (/deobfuscate), AND the Phase-4 investigation loop (/investigate). Without wiring
    # each factory the corresponding deployed endpoint runs with client=None and is
    # silently dead (the Phase-3 deobf trap; repeated for /investigate = the Phase-4
    # trap). Gated on the key so a keyless deploy degrades safely and never blocks.
    factory = _judge_client_factory if os.getenv("ANTHROPIC_API_KEY") else None
    # /investigate ALSO needs a live Splunk connection. Gate the splunk factory on BOTH
    # SPLUNK_HOST and SPLUNK_PASSWORD: SPLUNK_HOST is a compose literal (always set), so
    # gating on the password too keeps /investigate cheaply inert (splunk_not_configured,
    # fail-closed) until a run is deliberately configured with the read-only password in the
    # gitignored .env. Otherwise the service would attempt a live connect on every alert and
    # block on the TCP timeout whenever the host is deallocated. A HOST+password deploy against
    # a down host still fails safe, surfacing as splunk_outage (the caught connect error).
    splunk_factory = (
        _splunk_service_factory
        if (os.getenv("SPLUNK_HOST") and os.getenv("SPLUNK_PASSWORD"))
        else None
    )
    return create_app(retriever, settings,
                      judge_client_factory=factory,
                      deobf_client_factory=factory,
                      investigation_client_factory=factory,
                      splunk_service_factory=splunk_factory)


app = build_default_app()
