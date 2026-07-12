"""Structural + secret-scan tests for the generated honeypot-triage workflow.
Imports the in-memory workflow dict directly (no file I/O); the builder imports
only stdlib, so importing it is side-effect-free apart from building the dict."""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))  # so build_honeypot_triage_workflow imports

from build_honeypot_triage_workflow import N8N_PREGATE_SOURCE, workflow  # noqa: E402

NODES = {n["name"]: n for n in workflow["nodes"]}
CONNS = workflow["connections"]


def _targets(node_name, output_index=0):
    """Set of downstream node names from node_name's main output `output_index`."""
    main = CONNS.get(node_name, {}).get("main", [])
    if output_index >= len(main):
        return set()
    return {c["node"] for c in main[output_index]}


def test_subpipeline_nodes_present():
    for name in [
        "Deobf Pre-gate", "Is Encoded?", "deobfuscate", "Has Deobf IOCs?",
        "Build VT Requests", "enrich_virustotal", "Build Deobf Normalize Body",
        "Build Triage Body", "triage-verdict",
    ]:
        assert name in NODES, f"missing node: {name}"


def test_pregate_inserted_before_existing_brute_force_path():
    # Parse Alert now flows into the pre-gate, and the IF's FALSE output restores
    # the original Parse Alert -> Has IOC brute-force entry.
    assert _targets("Parse Alert") == {"Deobf Pre-gate"}
    assert _targets("Deobf Pre-gate") == {"Is Encoded?"}
    assert _targets("Is Encoded?", 0) == {"deobfuscate"}      # true
    assert _targets("Is Encoded?", 1) == {"Has IOC"}          # false -> unchanged path


def test_subpipeline_wired_to_triage_verdict():
    assert _targets("deobfuscate") == {"Has Deobf IOCs?"}
    assert _targets("Has Deobf IOCs?", 0) == {"Build VT Requests"}   # true: has IOCs
    assert _targets("Has Deobf IOCs?", 1) == {"Build Triage Body"}   # false: skip VT
    assert _targets("Build VT Requests") == {"enrich_virustotal"}
    assert _targets("enrich_virustotal") == {"Build Deobf Normalize Body"}
    assert _targets("Build Deobf Normalize Body") == {"deobf normalize"}
    assert _targets("deobf normalize") == {"Build Triage Body"}
    assert _targets("Build Triage Body") == {"triage-verdict"}


def test_pregate_node_embeds_canonical_source():
    js = NODES["Deobf Pre-gate"]["parameters"]["jsCode"]
    assert json.dumps(N8N_PREGATE_SOURCE) in js, "pre-gate must embed N8N_PREGATE_SOURCE verbatim"


def test_parse_alert_surfaces_alert_command():
    js = NODES["Parse Alert"]["parameters"]["jsCode"]
    assert "alert_command" in js


def test_terminal_nodes_present_and_wired():
    for name in ["Build Deobf Alert", "Add Deobf Alert", "Deobf Discord"]:
        assert name in NODES, f"missing node: {name}"
    assert _targets("triage-verdict") == {"Build Deobf Alert"}
    assert _targets("Build Deobf Alert") == {"Add Deobf Alert", "Deobf Discord"}


def test_deobfuscate_node_bounds_paid_retries():
    # Task 15 finding-2: /deobfuscate can make MULTIPLE paid Claude calls per request (one
    # per undecoded layer). An unbounded retryOnFail (n8n default maxTries=3) with no request
    # timeout could re-charge every call on a transient slow-call failure. Bound the retries
    # and set an explicit request timeout so a retry storm cannot multiply the paid cost.
    d = NODES["deobfuscate"]
    assert d.get("retryOnFail") is True
    assert d.get("maxTries") == 2                          # bounded (n8n default is 3)
    assert d["parameters"]["options"].get("timeout")       # explicit request timeout (ms)


def test_deobf_branch_never_reaches_verify_or_gate():
    # The deterministic verdict is authoritative: no de-obf node may route into
    # the Opus credibility path (verify/Gate). Regression guard for the invariant.
    deobf_nodes = ["Deobf Pre-gate", "Is Encoded?", "deobfuscate", "Has Deobf IOCs?",
                   "Build VT Requests", "enrich_virustotal", "Build Deobf Normalize Body",
                   "deobf normalize", "Build Triage Body", "triage-verdict", "Build Deobf Alert"]
    for n in deobf_nodes:
        for i in (0, 1):
            assert "verify" not in _targets(n, i) and "Gate" not in _targets(n, i), \
                f"{n} routes into the Opus credibility path"


def test_terminal_does_not_inline_raw_payload():
    # Ground-truth invariant at the presentation layer: the notification must NOT
    # inline attacker-controlled decoded bytes or model advisory text.
    js = NODES["Build Deobf Alert"]["parameters"]["jsCode"]
    assert "final_plaintext" not in js
    assert "advisory_intent" not in js


def test_workflow_json_round_trips():
    assert json.loads(json.dumps(workflow, ensure_ascii=False)) == workflow


def test_investigate_node_present_and_wired():
    names = {n["name"] for n in workflow["nodes"]}
    assert "investigate" in names
    inv = next(n for n in workflow["nodes"] if n["name"] == "investigate")
    assert inv["onError"] == "continueRegularOutput"
    conns = workflow["connections"]
    assert conns["retrieve"]["main"][0][0]["node"] == "investigate"
    assert conns["investigate"]["main"][0][0]["node"] == "Build Opus Input"


def test_verify_body_includes_scope_evidence():
    extract = next(n for n in workflow["nodes"] if n["name"] == "Extract Result")
    assert "scope_evidence" in extract["parameters"]["jsCode"]


def test_scope_findings_in_tool_schema():
    tool = next(n for n in workflow["nodes"] if n["name"] == "submit_triage_result")
    assert "scope_findings" in json.dumps(tool)


def test_parse_alert_emits_event_time_and_investigate_body_references_it():
    # Load-bearing (spec section 3 / red-team F-scope-time): a windowed Splunk
    # query anchored on wall-clock "now" instead of the alert's real event time
    # would silently return 0 rows and manufacture a false "no activity" scope.
    # Parse Alert must expose a single normalized event_time, and the
    # investigate node's outbound body must reference it.
    parse_js = NODES["Parse Alert"]["parameters"]["jsCode"]
    assert "event_time" in parse_js
    inv = next(n for n in workflow["nodes"] if n["name"] == "investigate")
    assert "event_time" in json.dumps(inv["parameters"])


def test_deployed_json_is_byte_identical_to_builder_output():
    # Invariant: JSON/honeypot-triage.json (what n8n actually imports) must be
    # byte-identical to what running build_honeypot_triage_workflow.py produces.
    # Replicate the builder's __main__ block EXACTLY: json.dump(workflow, fh,
    # indent=2, ensure_ascii=False) with fh opened the same way -- text mode,
    # encoding="utf-8", default (universal) newline handling -- so any
    # platform newline translation the builder applied when it wrote the
    # checked-in file is reproduced here too, without touching disk.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    deployed_path = os.path.join(repo_root, "JSON", "honeypot-triage.json")

    with open(deployed_path, "rb") as fh:
        deployed_bytes = fh.read()

    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="utf-8", newline=None)
    json.dump(workflow, wrapper, indent=2, ensure_ascii=False)
    wrapper.flush()
    wrapper.detach()  # release buf without closing it
    expected_bytes = buf.getvalue()

    assert deployed_bytes == expected_bytes, (
        "JSON/honeypot-triage.json is out of sync with "
        "build_honeypot_triage_workflow.py's output -- regenerate it "
        "(python infra/honeypot/build_honeypot_triage_workflow.py) and "
        "commit the result"
    )


def test_no_live_secret_only_placeholders():
    s = json.dumps(workflow, ensure_ascii=False)
    # No Anthropic key material anywhere.
    assert "sk-ant-" not in s
    # Every credential id is the REPLACE_ME placeholder.
    for n in workflow["nodes"]:
        for cred in (n.get("credentials") or {}).values():
            assert cred.get("id") == "REPLACE_ME", f"non-placeholder cred in {n['name']}"
    # Discord webhooks are placeholders only (no real webhook path).
    assert "discord.com/api/webhooks/REPLACE_ME" in s
    assert "discord.com/api/webhooks/" in s
    import re as _re
    real_hooks = [m for m in _re.findall(r"discord\.com/api/webhooks/([^\"'\\ ]+)", s) if m != "REPLACE_ME"]
    assert real_hooks == [], f"non-placeholder Discord webhook(s): {real_hooks}"
