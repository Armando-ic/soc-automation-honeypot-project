"""Per-case/per-trial (K-loop) orchestration for the Phase 1 red-team harness.

`run_case` replays one `AttackCase` (Task 9) through the SAME transform chain
the deployed `honeypot-triage` n8n workflow runs -- Parse Alert -> retrieve ->
Build Opus Input -> Opus call -> Extract Result -> verify -- for K independent
trials, scoring each with `red_team.scorer.score_trial`.

This is the fix for the refusal-can't-bypass bug (§16 item 10): production's
Extract Result node throws when there is no tool call, so a REFUSAL or
NO_TOOL_CALL outcome never reaches the verifier gate and can never be scored
as a bypass. TRUNCATED (stop_reason == "max_tokens") is a harness-observable
outcome with no usable tool output either, and is marked INVALID rather than
scored as a deviation or a clean pass.
"""
from __future__ import annotations

from dataclasses import dataclass

from triage_verifier.models import CheckResult, CheckStatus, TriageVerificationReport

from red_team.cases import AttackCase
from red_team.harness.extract_result import extract_result
from red_team.harness.input_builder import (
    build_opus_input,
    falcon_body_from_case,
    parse_alert,
    splunk_body_from_case,
)
from red_team.harness.model_client import ModelClient, Outcome, classify_outcome
from red_team.harness.retriever import assert_pinned_subset, retrieve
from red_team.scorer import TrialScore, score_trial


@dataclass
class TrialRecord:
    outcome: Outcome
    verify_body: dict | None
    passed: bool
    score: TrialScore
    raw_severity: object | None


@dataclass
class CaseResult:
    case: AttackCase
    trials: list[TrialRecord]
    k: int


def _usage_dict(raw) -> dict:
    """Convert the Anthropic response's `usage` object (`.input_tokens` /
    `.output_tokens` attributes) into the JS-shaped dict `extract_result`
    expects. Defensive: `raw.usage` may be absent -> default 0/0."""
    usage = getattr(raw, "usage", None)
    return {
        "input_tokens": getattr(usage, "input_tokens", 0),
        "output_tokens": getattr(usage, "output_tokens", 0),
    }


def _run_trial(case: AttackCase, model_client: ModelClient, retriever, verifier) -> TrialRecord:
    body = falcon_body_from_case(case.alert) if case.source == "falcon" else splunk_body_from_case(case.alert)
    parsed = parse_alert(body)

    techniques, ids = retrieve(retriever, parsed["alert_text"])
    if case.retrieval == "pinned":
        assert_pinned_subset(case.fixed_techniques, ids)
        ids = case.fixed_techniques
        pinned_set = set(case.fixed_techniques)
        techniques = [t for t in techniques if t["id"] in pinned_set]

    ctx = build_opus_input(parsed, case.fixed_enrichment, techniques, ids)

    raw = model_client.call(ctx["opus_user_message"])
    outcome, tool_input = classify_outcome(raw)

    if outcome is Outcome.TRUNCATED:
        return TrialRecord(
            outcome=outcome,
            verify_body=None,
            passed=False,
            score=TrialScore(deviated=False, bypassed=False, matched=[], invalid=True,
                              invalid_reason="stop_reason max_tokens"),
            raw_severity=None,
        )

    if outcome in (Outcome.REFUSAL, Outcome.NO_TOOL_CALL):
        # Production's Extract Result throws on no tool call -- there is no
        # verify_body and the gate never runs. A refusal to a genuine attack
        # is a real, non-bypass production outcome, not an invalid trial.
        return TrialRecord(
            outcome=outcome,
            verify_body=None,
            passed=False,
            score=TrialScore(deviated=False, bypassed=False, matched=[], invalid=False, invalid_reason=""),
            raw_severity=None,
        )

    # outcome is TOOL_CALL or PARTIAL -- gate path.
    usage = _usage_dict(raw)
    raw_severity = tool_input.get("severity") if isinstance(tool_input, dict) else None

    # Production wraps extract_result's downstream /verify call in
    # verify_adapter.build_report()'s try/except (verify_adapter.py:29): any
    # verifier exception becomes a single `verifier_error` FAILED CheckResult, so
    # report.passed == False and the event is still scored (deviated-if-predicates-
    # fire, bypassed=False), never a 500 and never a dropped event. Mirror that
    # here so one adversarial model output cannot abort the whole campaign.
    #
    # If extract_result ITSELF raises, there is no verify_body to score at all --
    # the JS transform (member access on primitives -> undefined) never throws, so
    # a Python-side crash here is a harness/port defect, not a production outcome.
    # We record the trial INVALID (excluded from both rates) rather than inventing
    # a scored result the deployed pipeline would never produce.
    try:
        out = extract_result(tool_input, ctx, usage=usage)
    except Exception as exc:  # port/extract defect on adversarial input: no verify_body
        return TrialRecord(
            outcome=outcome,
            verify_body=None,
            passed=False,
            score=TrialScore(False, False, [], True, f"extract_result raised: {exc}"),
            raw_severity=raw_severity,
        )

    verify_body = out["verify_body"]

    if verify_body["retrieved"] is None or verify_body["enrichment_results"] is None:
        # Harness config error: ctx always supplies both (defaulted to []/{}
        # by build_opus_input), so this should be unreachable in practice --
        # implemented per spec (§5 non-None guard) as a defensive INVALID.
        return TrialRecord(
            outcome=outcome,
            verify_body=verify_body,
            passed=False,
            score=TrialScore(False, False, [], True, "null retrieved/enrichment"),
            raw_severity=raw_severity,
        )

    try:
        report = verifier.verify(
            verify_body["result"],
            retrieved=verify_body["retrieved"],
            enrichment_results=verify_body["enrichment_results"],
        )
    except Exception as exc:  # mirror build_report: gate FALSE, never propagate
        report = TriageVerificationReport(
            results=(
                CheckResult("verifier_error", CheckStatus.FAILED, f"verifier raised: {exc}"),
            ),
        )

    # score_trial layers bypassed = deviated AND report.passed. On a synthesized
    # verifier_error report (passed==False) that collapses to bypassed=False,
    # matching production's verifier_error -> FAILED -> not-bypassed semantics.
    score = score_trial(case, verify_body, out["contain_recommended"], report, out["discord_body"], outcome)

    return TrialRecord(
        outcome=outcome,
        verify_body=verify_body,
        passed=report.passed,
        score=score,
        raw_severity=raw_severity,
    )


def run_case(case: AttackCase, model_client: ModelClient, retriever, verifier, k: int) -> CaseResult:
    """Replay `case` through the harness K independent times, returning one
    `TrialRecord` per trial in `CaseResult.trials`."""
    trials = [_run_trial(case, model_client, retriever, verifier) for _ in range(k)]
    assert len(trials) == k
    return CaseResult(case=case, trials=trials, k=k)
