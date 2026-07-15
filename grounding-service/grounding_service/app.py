"""FastAPI surface: /retrieve, /verify, /normalize, /health."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from grounding_service import brake as brk
from grounding_service import falcon as fal
from grounding_service.config import Settings
from grounding_service.feed_state import (
    load_feed_state,
    record_post,
    save_feed_state,
    summarize,
)
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


_HOST_FEED_CAP = 5000
_HOST_FEED_TIMEOUT_S = 30.0


def host_feed_spl(splunk_host_ip: str) -> str:
    """The host feeder's search. Four details are load-bearing, not decoration.

    * `sourcetype=XmlWinEventLog`, NOT `sourcetype=*Sysmon*`. splunk-inputs.conf sets
      renderXml=1, so Sysmon lands under XmlWinEventLog -- a string with no "Sysmon" in it.
      The wildcard the A8 doc has carried since d39a1c4 matches ZERO events, forever, silently.
      Live receipt (2026-07-15, 24h): XmlWinEventLog EventCode=3 -> 15,935; *Sysmon* -> 0.
    * The leading `search` is REQUIRED. splunklib's jobs.create rejects a bare `index=...`
      (every catalog.py template carries it for the same reason). Drop it and the search errors,
      run_catalog_query swallows that into outcome="error", and the feed is red forever.
    * SCOPED TO THE ROWS evaluate_egress CAN ACT ON, so the result cap is reachable only by a
      genuine fan-out. Unscoped, this ships every (ip,port) pair the box touches -- including
      NSG-DENIED connect ATTEMPTS, which Sysmon logs anyway (it hooks the guest network stack;
      the NSG drops the packet out in the Azure fabric). An attacker port-scanning would emit
      thousands of rows that never leave the box, parse_envelope keeps results[:cap] ordered by
      DestinationIp, and the real 443 fan-out rows could be truncated straight out of the feed.
      Scoped, 5000 rows implies >2500 watched destinations, which trips fan-out on its own --
      which is what makes riding through capped_incomplete sound rather than merely assumed.
      The Splunk host is an explicit OR because splunk_nonuf trips on port != 9997, so it needs
      Splunk rows on ANY port, which a watch-ports filter could never admit. NOTE THE SILENT
      DEGRADE: that OR clause exists only when SPLUNK_HOST_IP is set in the gitignored .env
      (SPLUNK_HOST_IP is the Splunk PUBLIC ip the brake watches FOR; it is NOT SPLUNK_HOST, the
      committed compose literal used to CONNECT). Unset, it defaults to "" and splunk_nonuf dies
      twice over -- no Splunk rows are shipped, and evaluate_egress's `dst_ip == splunk_host_ip`
      can never match a truthy ip anyway. Nothing 503s, nothing goes red, /brake/nsg-status still
      reports configured: green and dead, the exact class this endpoint exists to refuse.
    * `| table dst_ip, dst_port` drops stats' `count`: the brake contract never reads it. This
      pre-aggregation to one row per distinct (dst_ip, dst_port) is also precisely why
      BRAKE_CONN_RATE_MAX cannot fire -- see test_egress_rate_is_dead_against_both_real_feeders.

    KNOWN, bounded, not filtered: EID3 is machine-wide, not outbound-only, so an INBOUND
    connection on a watched port arrives with dst_ip = the honeypot's own address and counts as
    one distinct destination. Every inbound row shares that address, so the overstatement is
    capped at +1. `Initiated=true` would remove it but adds a filter whose failure mode is a
    silently empty feed, which is a worse trade than being off by one.

    splunk_host_ip is operator-set from the gitignored .env, never attacker-controlled.
    """
    watched = "DestinationPort IN (80,443)"
    if splunk_host_ip:
        watched += f' OR DestinationIp="{splunk_host_ip}"'
    return (
        f"search index=honeypot sourcetype=XmlWinEventLog EventCode=3 earliest=-5m ({watched})"
        " | stats count by DestinationIp, DestinationPort"
        " | rename DestinationIp as dst_ip, DestinationPort as dst_port"
        " | table dst_ip, dst_port"
    )


class BrakeEvaluateRequest(BaseModel):
    # Strict on the container, lenient on the elements.
    #
    # REQUIRED (no default): a body with no `events` key is a body we do not understand, and
    # defaulting it to [] read that as "all quiet" -- which is how the Splunk built-in webhook
    # envelope scored 200/trip:false against this app.
    # BE HONEST ABOUT ITS REACH: this is defence-in-depth for a DIRECT post to /brake/evaluate,
    # and it is INERT through the brake webhook, which is the only path production uses. One hop
    # upstream, honeypot-brake's Normalize Events does
    #     const events = Array.isArray(body.events) ? body.events : [];
    # so an unintelligible body becomes events:[] before Pydantic ever sees it, and the result is
    # 200/trip:false, NOT a 422. The real fix for the Splunk-envelope green-and-dead failure is
    # the PULL feeder (/brake/host-feed), not this validator. Making Normalize Events fail closed
    # instead was considered and REJECTED: this webhook is unauthenticated, so "unintelligible
    # body -> trip" hands anyone who can reach it a one-request remote box-killer. On this brake,
    # "fail closed" and "safe" are not synonyms -- closed means the capture dies.
    #
    # BARE `list` (not list[dict]): per-element validation 422s the whole call over one junk row,
    # and through the webhook that 422 IS live-reachable (Normalize Events passes elements through
    # untouched, so a list with junk in it reaches Pydantic intact) -> evaluate's error output ->
    # nsg_deny -> all egress denied. evaluate_egress already skips non-dict rows by design, so
    # row-level junk is its call to make, not the validator's.
    events: list
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
    azure_brake_session_factory: Callable[[], object] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    app = FastAPI(title="grounding-service", version="0.1.0")

    # Injected so the liveness watermark is testable without wall-clock. The two known-red falcon
    # watermark tests are red exactly because load_state falls back to datetime.now() at the
    # endpoint boundary and their assertions rot against real time. Do not repeat that here.
    _now = clock or (lambda: datetime.now(timezone.utc))

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

    @app.get("/brake/host-feed")
    def brake_host_feed() -> dict:
        """Pull the honeypot's recent Sysmon EID3 connections for the brake to judge.

        This is the FAST feeder's read side. Splunk's built-in webhook alert action cannot
        deliver the {events, source} contract (fixed envelope, first result row only), so the
        feeder pulls: n8n Schedule Trigger -> GET here -> POST the contract to the brake.

        FAILS LOUD, NEVER EMPTY -- and note this is the exact opposite of /investigate, which
        degrades a Splunk outage to a well-typed empty result because a dead Splunk must not
        block triage. Here an empty feed reads to evaluate_egress as "all quiet" and is
        byte-identical to a healthy idle box, so a silent degrade would leave the fast feeder
        inert while every n8n execution stayed green. Any uncertainty surfaces as a 503: the
        execution goes red, nothing is POSTed, a human sees it. Do NOT "improve" this into a
        well-typed empty response.
        """
        if splunk_service_factory is None:
            raise HTTPException(status_code=503, detail="splunk_not_configured")
        try:
            from splunk_investigator.splunk_client import run_catalog_query
            service = splunk_service_factory()
        except Exception:
            raise HTTPException(status_code=503, detail="splunk_outage")

        res = run_catalog_query(service, host_feed_spl(settings.splunk_host_ip),
                                "brake_host_feed", {}, _HOST_FEED_CAP, _HOST_FEED_TIMEOUT_S)
        # run_catalog_query never raises: bad SPL, a dead indexer, an expired
        # phase4_investigator password and a role regression ALL arrive here as outcome="error"
        # with rows=(). That is the one shape that must never become a 200.
        if res.outcome == "error":
            raise HTTPException(status_code=503, detail="splunk_error")

        # capped_incomplete does NOT imply rows >= cap: parse_envelope's truncation limb is
        # `any(_is_truncation_message(m) ...) or len(results) > result_cap`, and the MESSAGE limb
        # fires independently of row count on any WARN containing "truncat"/"incomplete". So a
        # degraded Splunk can answer capped_incomplete with ZERO rows -- an admission that we do
        # not know, which must never render as "the box is quiet".
        if res.outcome == "capped_incomplete" and res.row_count == 0:
            raise HTTPException(status_code=503, detail="splunk_error")

        # capped_incomplete WITH rows rides through on purpose, and 503-ing it outright would be
        # a fail-OPEN: the SPL is scoped to watched rows, so a genuine overflow means >2500
        # watched destinations -- the massive fan-out this brake exists to catch. Refusing to
        # POST then would mean the brake never fires during the exact event.
        events = [{"dst_ip": r.get("dst_ip", ""), "dst_port": r.get("dst_port", "")}
                  for r in res.rows]
        return {"events": events, "source": "splunk",
                "outcome": res.outcome, "row_count": res.row_count}

    @app.post("/brake/evaluate")
    def brake_evaluate(req: BrakeEvaluateRequest) -> dict:
        out = brk.evaluate_egress(
            req.events,
            splunk_host_ip=settings.splunk_host_ip,
            distinct_dst_max=settings.brake_distinct_dst_max,
            conn_rate_max=settings.brake_conn_rate_max,
        )
        out["source"] = req.source
        # Liveness watermark. Recorded for EVERY call including quiet ones (distinct_dst 0) --
        # arrival is the proof, not content, and a quiet box is byte-identical to a dead feeder
        # from the brake's side. Both feeders POST here, so this sees both.
        #
        # The bare except is deliberate and load-bearing, not laziness. This handler is on the
        # PROVEN fire path: the evaluate node runs onError=continueErrorOutput with its error
        # output wired straight to nsg_deny, so ANY exception escaping here DENIES ALL EGRESS and
        # contains the box. A disk-full or a read-only mount must cost us telemetry, never the
        # honeypot. Guarded by test_a_broken_watermark_cannot_strangle_the_box.
        try:
            st = load_feed_state(settings.brake_feed_state_path)
            st = record_post(st, now=_now(), distinct_dst=out["distinct_dst"],
                             conn_count=out["conn_count"], source=req.source,
                             trip=bool(out["trip"]))
            save_feed_state(settings.brake_feed_state_path, st)
        except Exception:
            pass
        return out

    @app.get("/brake/feed-status")
    def brake_feed_status() -> dict:
        """Is a feeder actually alive, and what does its traffic look like?

        The brake cannot answer either question: evaluate_egress([]) and a real quiet box are the
        same response. This is the SOC-side watermark that can, and it survives a trip -- which
        matters, because a trip severs the honeypot's own 9997 forwarding (deny @100 beats
        allow-splunk-telemetry @1000), killing every honeypot-side signal exactly when it counts.

        `stale` is the B7 gate: do not open the box while it is true. And it is ALWAYS a real
        fault -- a trip cannot cause it, so never wave one off as "the brake must have fired".
        The severing kills the feeder's CONTENT (zero rows, forever), not its heartbeat: the
        feeder chain is SOC-side, so it keeps POSTing an empty list every minute and `stale`
        stays FALSE. See test_a_trip_does_not_make_the_feeder_read_stale.

        `max_distinct_dst` is the threshold baseline BRAKE_DISTINCT_DST_MAX has never had: the
        closed-box measurement is 0, i.e. the regime where the feeder does not matter.
        """
        return summarize(load_feed_state(settings.brake_feed_state_path),
                         now=_now(), stale_after_s=settings.brake_feed_stale_s)

    def _brake_configured() -> bool:
        return bool(
            settings.brake_enabled and settings.azure_tenant_id and settings.azure_client_id
            and settings.azure_client_secret and settings.honeypot_subscription_id
            and settings.honeypot_nsg_rg and settings.honeypot_nsg_name
            and azure_brake_session_factory is not None
        )

    @app.post("/brake/nsg-deny")
    def brake_nsg_deny() -> dict:
        empty = {"fired": False, "access": "", "provisioning_state": ""}
        if not _brake_configured():
            return {**empty, "reason": "brake_not_configured"}
        try:
            session = azure_brake_session_factory()
            token = brk.fetch_token(session, tenant=settings.azure_tenant_id,
                                    client_id=settings.azure_client_id,
                                    client_secret=settings.azure_client_secret)
            res = brk.nsg_deny_egress(session, token,
                                      subscription=settings.honeypot_subscription_id,
                                      resource_group=settings.honeypot_nsg_rg,
                                      nsg=settings.honeypot_nsg_name,
                                      rule_name=settings.honeypot_nsg_deny_rule,
                                      priority=settings.honeypot_nsg_deny_priority)
            return {"fired": True, "reason": "", "access": res["access"],
                    "provisioning_state": res["provisioning_state"]}
        except Exception:
            return {**empty, "reason": "brake_error"}

    @app.get("/brake/nsg-status")
    def brake_nsg_status() -> dict:
        if not _brake_configured():
            return {"configured": False, "access": "", "provisioning_state": ""}
        try:
            session = azure_brake_session_factory()
            token = brk.fetch_token(session, tenant=settings.azure_tenant_id,
                                    client_id=settings.azure_client_id,
                                    client_secret=settings.azure_client_secret)
            st = brk.nsg_rule_status(session, token,
                                     subscription=settings.honeypot_subscription_id,
                                     resource_group=settings.honeypot_nsg_rg,
                                     nsg=settings.honeypot_nsg_name,
                                     rule_name=settings.honeypot_nsg_deny_rule)
            return {"configured": True, **st}
        except Exception:
            return {"configured": True, "access": "unknown", "provisioning_state": "error"}

    return app
