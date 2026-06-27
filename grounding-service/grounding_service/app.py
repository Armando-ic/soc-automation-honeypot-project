"""FastAPI surface: /retrieve, /verify, /normalize, /health."""
from __future__ import annotations

from typing import Callable

from fastapi import FastAPI
from pydantic import BaseModel

from grounding_service.config import Settings
from grounding_service.enrichment import build_enrichment_results
from grounding_service.retriever import AttackRetriever
from grounding_service.verify_adapter import build_report


class RetrieveRequest(BaseModel):
    alert_text: str
    top_k: int | None = None


class NormalizeRequest(BaseModel):
    items: list[dict]


class VerifyRequest(BaseModel):
    result: dict
    retrieved: list[str] | None = None
    enrichment_results: dict[str, str] | None = None
    run_meta: dict = {}


def create_app(
    retriever: AttackRetriever,
    settings: Settings,
    *,
    judge_client_factory: Callable[[], object] | None = None,
) -> FastAPI:
    app = FastAPI(title="grounding-service", version="0.1.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/retrieve")
    def retrieve(req: RetrieveRequest) -> dict:
        k = req.top_k or settings.top_k_default
        techniques = retriever.search(req.alert_text, top_k=k)
        return {"techniques": techniques, "ids": [t["id"] for t in techniques]}

    @app.post("/normalize")
    def normalize(req: NormalizeRequest) -> dict:
        return {"enrichment_results": build_enrichment_results(req.items)}

    @app.post("/verify")
    def verify(req: VerifyRequest) -> dict:
        client = None
        if judge_client_factory is not None:
            try:
                client = judge_client_factory()
            except Exception:  # judge outage must never block triage
                client = None
        return build_report(
            req.result,
            retrieved=req.retrieved,
            enrichment_results=req.enrichment_results,
            run_meta=req.run_meta,
            settings=settings,
            client=client,
        )

    return app
