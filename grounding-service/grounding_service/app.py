"""FastAPI surface: /retrieve, /verify, /normalize, /health."""
from __future__ import annotations

from typing import Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from grounding_service import falcon as fal
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


class FalconPlanRequest(BaseModel):
    candidate_ids: list[str]
    cap: int | None = None


class FalconMapRequest(BaseModel):
    alerts: list[dict]


class FalconAdvanceRequest(BaseModel):
    results: list[dict]


class FalconContainGuardRequest(BaseModel):
    resolved_ids: list[str]


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

    @app.get("/falcon/state")
    def falcon_state() -> dict:
        return fal.load_state(settings.state_path)

    @app.post("/falcon/plan")
    def falcon_plan(req: FalconPlanRequest) -> dict:
        st = fal.load_state(settings.state_path)
        cap = req.cap if req.cap is not None else settings.falcon_poll_cap
        return {
            "ids": fal.select_new_alert_ids(req.candidate_ids, st["seen"], cap),
            "watermark": st["watermark"],
        }

    @app.post("/falcon/map")
    def falcon_map(req: FalconMapRequest) -> dict:
        # map_alerts sorts oldest-first by `created` (don't trust entities/alerts/v2 to preserve order)
        return {"items": fal.map_alerts(req.alerts)}

    @app.post("/falcon/advance")
    def falcon_advance(req: FalconAdvanceRequest) -> dict:
        st = fal.load_state(settings.state_path)
        new = fal.advance_state(st, req.results)
        fal.save_state(settings.state_path, new)
        return new

    @app.post("/falcon/contain-guard")
    def falcon_contain_guard(req: FalconContainGuardRequest) -> dict:
        try:
            aid = fal.select_contain_aid(req.resolved_ids, settings.falcon_pinned_aid)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return {"aid": aid}

    return app
