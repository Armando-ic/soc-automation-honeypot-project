"""Structural + secret-scan tests for the generated honeypot-triage workflow.
Imports the in-memory workflow dict directly (no file I/O); the builder imports
only stdlib, so importing it is side-effect-free apart from building the dict."""
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
