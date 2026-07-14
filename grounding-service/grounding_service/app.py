"""FastAPI surface: /retrieve, /verify, /normalize, /health."""
from __future__ import annotations

from typing import Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from grounding_service import brake as brk
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
    scope_evidence: dict | None = None


class FalconPlanRequest(BaseModel):
    candidate_ids: list[str]
    cap: int | None = None


class FalconMapRequest(BaseModel):
    alerts: list[dict]


class FalconAdvanceRequest(BaseModel):
    results: list[dict]


class FalconContainGuardRequest(BaseModel):
    resolved_ids: list[str]


class DeobfuscateRequest(BaseModel):
    payload: str
    # H-ITEM1: ge=1 rejects max_bytes<=0 at the pydantic layer (422) before the
    # handler runs. None still means "no cap given, use the ceiling." Without
    # this, max_bytes=0 used to be swallowed by `0 or ceiling` (0 is falsy) and
    # silently process the FULL ceiling, and a negative value used to chop the
    # payload from the wrong end while always marking it truncated.
    max_bytes: int | None = Field(default=None, ge=1)


class BrakeEvaluateRequest(BaseModel):
    events: list[dict] = []
    source: str = ""


class TriageVerdictRequest(BaseModel):
    behavioral_hits: list[dict] = []
    ioc_verdicts: dict[str, str] = {}
    fully_resolved: bool = True
    flags: list[str] = []


class InvestigateRequest(BaseModel):
    # Free-form: carries src_ip/host/user/event_time/alert_text/
    # enrichment_verdicts/candidate_techniques. Kept as a plain dict (not a
    # fully typed model) since splunk_investigator's pregate/agent already
    # tolerate missing keys via alert.get(...) -- typing it here would just
    # duplicate that contract and risk drifting from it.
    alert: dict


def _empty_investigation(flags: list[str] | None = None) -> dict:
    """The well-typed empty result (spec section 2.1): a fresh dict every call
    so no caller can mutate a shared literal across requests."""
    return {
        "investigated": False,
        "scope_evidence": {"claims": [], "queries_run": []},
        "transcript": [],
        "flags": list(flags) if flags is not None else [],
        "advisory_reasoning": "",
    }


def _scrub_surrogates(obj):
    """Replace lone surrogate code points (unencodable as UTF-8) anywhere in the
    outgoing response so Starlette's JSONResponse.render never 500s. Applied ONLY to
    the response dict, AFTER the verdict/IOC/behavioral values were computed from the
    true plaintext -- so this cannot move the verdict (verdict-safe by construction)."""
    if isinstance(obj, str):
        return obj.encode("utf-8", "replace").decode("utf-8")
    if isinstance(obj, list):
        return [_scrub_surrogates(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub_surrogates(v) for k, v in obj.items()}
    return obj


def create_app(
    retriever: AttackRetriever,
    settings: Settings,
    *,
    judge_client_factory: Callable[[], object] | None = None,
    deobf_client_factory: Callable[[], object] | None = None,
    investigation_client_factory: Callable[[], object] | None = None,
    splunk_service_factory: Callable[[], object] | None = None,
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
            scope_evidence=req.scope_evidence,
        )

    @app.post("/deobfuscate")
    def deobfuscate(req: DeobfuscateRequest) -> dict:
        from malware_triage.behavioral import behavioral_hits
        from malware_triage.config import load_config
        from malware_triage.extractor import extract_from_result
        from malware_triage.gate import decode_and_verify

        cfg = load_config()
        # F4/D6: read req.max_bytes (was declared but never used) and cap the
        # attacker payload BEFORE the engine touches it. min(...) means max_bytes
        # can only LOWER the cap, never raise it above the config ceiling. Chopping
        # a tail is the D4 false-clean hazard, so signal truncation -> the verdict
        # floors to unknown, never a silent clean.
        # H-ITEM1: max_bytes is now guaranteed by pydantic (ge=1) to be either
        # None or >= 1, so this no longer needs to rely on `or` truthiness --
        # spelled out explicitly so a reader doesn't have to reason about that
        # coupling to know 0 can't sneak through.
        cap = (min(req.max_bytes, cfg.max_payload_bytes)
               if req.max_bytes is not None else cfg.max_payload_bytes)
        entry_truncated = len(req.payload) > cap
        payload = req.payload[:cap]
        client = None
        if deobf_client_factory is not None:
            try:
                client = deobf_client_factory()
            except Exception:      # a Claude outage must never block triage
                client = None
        result = decode_and_verify(payload, client, cfg)
        if entry_truncated and "truncated" not in result.flags:
            result.flags.append("truncated")
        result.iocs = extract_from_result(result)
        hits = behavioral_hits(result)
        # H-ITEM2: scrub AFTER verdict/IOC/behavioral values are already computed
        # from the true (unscrubbed) plaintext, so this can't move the verdict --
        # it only stops a raw lone surrogate from crashing the JSON response.
        return _scrub_surrogates({
            "verified_layers": [
                {"transform": l.transform, "params": l.params, "source": l.source,
                 "input_sha256": l.input_sha256, "output_sha256": l.output_sha256}
                for l in result.verified_layers
            ],
            "final_plaintext": result.final_plaintext,
            "rejected_layers": [
                {"transform": r.transform, "reason": r.reason} for r in result.rejected_layers
            ],
            "iocs": [
                {"value": i.value, "ioc_type": i.ioc_type, "defanged_original": i.defanged_original}
                for i in result.iocs
            ],
            "advisory_intent": result.advisory_intent,
            "flags": result.flags,
            # forwarded verbatim by n8n to /triage-verdict after the VT lookups:
            "verdict_inputs": {
                "behavioral_hits": [
                    {"rule_id": h.rule_id, "category": h.category, "evidence": h.evidence} for h in hits
                ],
                "fully_resolved": result.fully_resolved,
                "flags": result.flags,
            },
        })

    @app.post("/triage-verdict")
    def triage_verdict(req: TriageVerdictRequest) -> dict:
        from malware_triage.models import BehavioralHit, DeobfuscationResult
        from malware_triage.verdict import fuse

        result = DeobfuscationResult(fully_resolved=req.fully_resolved, flags=list(req.flags))
        # F7/D5: a malformed hit must NOT be silently dropped (that could launder
        # a suspicious verdict into a clean one) or 500 with a bare KeyError.
        if any("rule_id" not in h for h in req.behavioral_hits):
            raise HTTPException(status_code=422, detail="behavioral hit missing rule_id")
        hits = [BehavioralHit(h["rule_id"], h.get("category", "other"), h.get("evidence", ""))
                for h in req.behavioral_hits]
        v = fuse(result, req.ioc_verdicts, hits)
        return {"verdict": v.verdict, "evidence": v.evidence, "flags": v.flags}

    @app.post("/investigate")
    def investigate_endpoint(req: InvestigateRequest) -> dict:
        # Phase 4 Task 11 / spec 2.1: this handler must NEVER 500. The
        # WHOLE body below is wrapped in a catch-all -- stronger than
        # /deobfuscate above, which only guards the client factory call.
        # Any failure anywhere (a bad import, a pregate bug, a malformed
        # alert, an engine exception) degrades to the well-typed empty
        # result, never propagates.
        try:
            from splunk_investigator.agent import investigate as run_investigation
            from splunk_investigator.config import load_config
            from splunk_investigator.pregate import should_investigate

            cfg = load_config()
            ok, reason = should_investigate(req.alert, cfg)
            if not ok:
                # investigated stays False; carry the pregate's reason
                # (no_pivot / deduped / budget_exhausted / kill_switch) as
                # the ONLY flag so callers can tell why nothing ran.
                return _empty_investigation([reason])

            if investigation_client_factory is None:
                return _empty_investigation(["claude_not_configured"])
            try:
                client = investigation_client_factory()
            except Exception:          # a Claude outage must never block triage
                return _empty_investigation(["claude_outage"])

            if splunk_service_factory is None:
                return _empty_investigation(["splunk_not_configured"])
            try:
                service = splunk_service_factory()
            except Exception:          # a Splunk outage must never block triage
                return _empty_investigation(["splunk_outage"])

            result = run_investigation(req.alert, client=client, splunk_service=service, cfg=cfg)
            return {
                "investigated": result.investigated,
                "scope_evidence": {
                    # LOAD-BEARING: FLAT, type + fields merged into one dict
                    # (not nested under a "fields" key) -- Task 10's
                    # verifier does field-for-field equality against this
                    # exact shape.
                    "claims": [{"type": c.type, **c.fields} for c in result.scope_evidence.claims],
                    "queries_run": [dict(q) for q in result.scope_evidence.queries_run],
                },
                # Task 17 deliverable #3: the agent's turn-by-turn decision
                # trace (each {turn, tool, params, result}), copied verbatim so
                # the single paid run captures which entity-bound query it chose,
                # in what order, and when it concluded -- the queries_run list
                # above is only the success-only subset. Each turn's `result` is
                # a rows-FREE summary ({outcome, row_count}, via _summarize_no_rows
                # in agent.py); the raw Splunk rows stay in-loop as the model's
                # tool_result and NEVER reach this published surface, so the
                # transcript carries no row data (or attacker-influenced Sysmon
                # free-text) the sanitized claims/queries_run don't already cover.
                "transcript": [dict(t) for t in result.transcript],
                "flags": list(result.flags),
                "advisory_reasoning": result.advisory_reasoning,
            }
        except Exception:
            return _empty_investigation()

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

    @app.post("/brake/evaluate")
    def brake_evaluate(req: BrakeEvaluateRequest) -> dict:
        out = brk.evaluate_egress(
            req.events,
            splunk_host_ip=settings.splunk_host_ip,
            distinct_dst_max=settings.brake_distinct_dst_max,
            conn_rate_max=settings.brake_conn_rate_max,
        )
        out["source"] = req.source
        return out

    return app
