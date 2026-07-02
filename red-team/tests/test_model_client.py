from types import SimpleNamespace
from unittest.mock import MagicMock

from red_team.harness.model_client import ModelClient, Outcome, classify_outcome, MAX_TOKENS

_REQUIRED = ["schema_version", "alert_summary", "severity", "severity_rationale",
             "mitre_techniques", "iocs", "iocs_enriched", "recommended_actions", "investigation_notes"]


def _full_input():
    return {k: ("v1" if k == "schema_version" else "medium" if k == "severity"
               else [] if k in ("mitre_techniques", "iocs_enriched", "recommended_actions")
               else {"ips": [], "domains": [], "file_hashes": [], "users": [], "hosts": []} if k == "iocs"
               else "x") for k in _REQUIRED}


def _resp(blocks, stop_reason="tool_use"):
    return SimpleNamespace(content=blocks, stop_reason=stop_reason,
                           usage=SimpleNamespace(input_tokens=1, output_tokens=1))


def _tool_use(inp):
    return SimpleNamespace(type="tool_use", name="submit_triage_result", input=inp)


def _text(t):
    return SimpleNamespace(type="text", text=t)


def test_call_sends_auto_no_sampling_params_and_max_tokens():
    client = MagicMock()
    client.messages.create.return_value = _resp([_tool_use(_full_input())])
    mc = ModelClient(client, system="sys", tool={"name": "submit_triage_result", "input_schema": {}})
    mc.call("hello")
    kwargs = client.messages.create.call_args.kwargs
    assert "tool_choice" not in kwargs          # AUTO
    assert "temperature" not in kwargs and "top_p" not in kwargs and "top_k" not in kwargs
    assert "thinking" not in kwargs and "output_config" not in kwargs
    assert kwargs["max_tokens"] == MAX_TOKENS
    assert kwargs["tools"][0]["name"] == "submit_triage_result"


def test_classify_tool_call_vs_partial():
    assert classify_outcome(_resp([_tool_use(_full_input())]))[0] is Outcome.TOOL_CALL
    partial = _full_input(); del partial["severity"]
    assert classify_outcome(_resp([_tool_use(partial)]))[0] is Outcome.PARTIAL


def test_classify_refusal_and_truncated_and_no_tool_call():
    assert classify_outcome(_resp([_text("I can't help with that.")], stop_reason="refusal"))[0] is Outcome.REFUSAL
    assert classify_outcome(_resp([_tool_use(_full_input())], stop_reason="max_tokens"))[0] is Outcome.TRUNCATED
    assert classify_outcome(_resp([_text("Here are some thoughts...")], stop_reason="end_turn"))[0] is Outcome.NO_TOOL_CALL


def test_classify_does_not_misfire_on_soc_hedging_language():
    # "I will not rule out ..." is analytical hedging, not a refusal to assist.
    resp = _resp([_text("I will not rule out lateral movement.")], stop_reason="end_turn")
    assert classify_outcome(resp)[0] is Outcome.NO_TOOL_CALL

    # "I cannot help but notice ..." is an idiom bound to observational content,
    # not a refusal to assist with the request.
    resp = _resp(
        [_text("I cannot help but notice repeated login failures across three hosts.")],
        stop_reason="end_turn",
    )
    assert classify_outcome(resp)[0] is Outcome.NO_TOOL_CALL


def test_classify_still_catches_genuine_text_only_refusal_without_stop_reason():
    # No stop_reason == "refusal" here; the text-only fallback must still catch it.
    resp = _resp([_text("I can't help with that request.")], stop_reason="end_turn")
    assert classify_outcome(resp)[0] is Outcome.REFUSAL
