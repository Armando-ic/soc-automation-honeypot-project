"""Structural + secret-scan tests for the generated honeypot-triage workflow.
Imports the in-memory workflow dict directly (no file I/O); the builder imports
only stdlib, so importing it is side-effect-free apart from building the dict."""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))  # so build_honeypot_triage_workflow imports

from build_honeypot_triage_workflow import N8N_PREGATE_SOURCE, workflow  # noqa: E402

NODES = {n["name"]: n for n in workflow["nodes"]}
CONNS = workflow["connections"]

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent


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


def test_prompt_instructs_verbatim_scope_findings_population():
    # T13-1: scope_findings is in the tool SCHEMA but the deployed system prompt never
    # told the model to fill it, so it stayed empty and the verifier's
    # _check_scope_findings_grounded short-circuited to PASSED on empty findings -- the
    # headline grounding was vacuously-passing, never demonstrated. The prompt must
    # instruct the model to copy the untrusted scope-evidence claims into scope_findings
    # VERBATIM (identical keys+values); the verifier fails closed on any edited/invented
    # finding, so a faithful copy grounds and a hallucination is caught.
    opus = next(n for n in workflow["nodes"] if n["name"] == "Opus triage")
    system = opus["parameters"]["options"]["system"]
    assert "scope_findings" in system, "prompt must name the scope_findings field"
    assert "verbatim" in system.lower(), \
        "prompt must instruct a VERBATIM copy of the scope-evidence claims into scope_findings"


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


def test_lb2_verify_body_result_threads_ground_truth_entities():
    # LB-2: the verifier reads src_ip/host from the triage RESULT dict
    # (verify_body.result). The generated Extract Result must thread
    # ctx.src_ip/ctx.host into that result OUT OF MODEL CONTROL (ctx wins over
    # any model-emitted key), else the scope-grounded HIGH/CRITICAL severity
    # path is permanently inert in production (final-review LB-2).
    js = NODES["Extract Result"]["parameters"]["jsCode"]
    # Thread the RAW pivot host (ctx.pivot_host, ''-when-absent), NOT the display
    # sentinel ctx.host ('unknown-host'): the verifier's critical-severity path
    # matches this against the engine-scoped host, so the sentinel must never be
    # the reference entity. A no-host alert -> '' -> honest fail-closed.
    assert "result: { ...r, src_ip: ctx.src_ip, host: ctx.pivot_host }" in js, \
        "verify_body.result must thread ctx.src_ip/ctx.pivot_host, not bare `result: r` or the display sentinel"


def test_lb3_investigate_receives_raw_pivot_entities_not_display_sentinel():
    # LB-3: the /investigate path must get the RAW host/user ('' when the alert
    # has none) so the engine pregate's no_pivot short-circuit is reachable and
    # no display sentinel ('unknown-host'/'unknown-user') leaks into the entity
    # scope. Parse Alert exposes pivot_host/pivot_user; investigate sends them.
    parse_js = NODES["Parse Alert"]["parameters"]["jsCode"]
    assert "const pivot_host = r.ComputerName || r.dest || r.host || '';" in parse_js
    assert "const pivot_user = r.user || r.Account_Name || '';" in parse_js
    inv = next(n for n in workflow["nodes"] if n["name"] == "investigate")
    inv_params = json.dumps(inv["parameters"])
    assert "pivot_host" in inv_params and "pivot_user" in inv_params, \
        "investigate must send the raw pivot_host/pivot_user, not the display host/user"


def test_lb1_event_time_falls_back_to_stats_surviving_fields():
    # LB-1: the live saved search ends in `stats ... earliest(_time) as earliest,
    # latest(_time) as latest by src_ip`, which DROPS _time. Parse Alert must
    # fall back to the stats-surviving epoch fields (the engine normalizes
    # epoch->ISO) instead of emitting '' -> render_error -> no claim.
    parse_js = NODES["Parse Alert"]["parameters"]["jsCode"]
    assert "r.latest" in parse_js and "r.earliest" in parse_js, \
        "splunk-path event_time must fall back to the stats-surviving latest/earliest"


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


# ---- Task A7: honeypot-brake generator (out-of-process, generates JSON/honeypot-brake.json) ----

def _gen_brake():
    subprocess.run([sys.executable, str(_HERE / "build_honeypot_brake_workflow.py")],
                   check=True, cwd=_ROOT)
    return json.loads((_ROOT / "JSON" / "honeypot-brake.json").read_text(encoding="utf-8"))


def test_brake_workflow_has_core_nodes():
    wf = _gen_brake()
    names = {n["name"] for n in wf["nodes"]}
    assert {"Brake Webhook", "Normalize Events", "evaluate", "Trip?",
            "nsg_deny", "Discord BRAKE FIRED"} <= names


def test_brake_workflow_calls_evaluate_and_nsg_deny_endpoints():
    wf = _gen_brake()
    urls = [n.get("parameters", {}).get("url", "") for n in wf["nodes"]]
    assert any(u.endswith("/brake/evaluate") for u in urls)
    assert any(u.endswith("/brake/nsg-deny") for u in urls)


def test_brake_workflow_evaluate_fails_closed_to_nsg_deny_on_error():
    wf = _gen_brake()
    ev = next(n for n in wf["nodes"] if n["name"] == "evaluate")
    assert ev.get("onError") == "continueErrorOutput"     # exposes an error output instead of halting
    conns = wf["connections"]["evaluate"]["main"]
    assert len(conns) == 2                                 # [0]=success, [1]=error
    assert conns[0][0]["node"] == "Trip?"                  # success -> normal trip check
    assert any(c["node"] == "nsg_deny" for c in conns[1])  # error -> fire the brake (fail closed)


def test_brake_workflow_reuses_aid_pinned_contain_guard():
    wf = _gen_brake()
    urls = [n.get("parameters", {}).get("url", "") for n in wf["nodes"]]
    assert any(u.endswith("/falcon/contain-guard") for u in urls)


def test_brake_workflow_secrets_are_placeholders():
    raw = (_ROOT / "JSON" / "honeypot-brake.json").read_text(encoding="utf-8")
    assert "REPLACE_ME" in raw
    assert "discord.com/api/webhooks/REPLACE_ME" in raw


def test_brake_workflow_contain_is_aid_pinned_not_hostname():
    wf = _gen_brake()
    contain = next(n for n in wf["nodes"] if n["name"] == "contain")
    body = contain["parameters"]["jsonBody"]
    assert "$('contain_guard').item.json.aid" in body     # fires off the guard-resolved AID
    assert "vm-honeypot-win" not in body                  # never the raw hostname


def test_brake_workflow_no_live_secret():
    wf = _gen_brake()
    s = json.dumps(wf, ensure_ascii=False)
    # No Anthropic key material anywhere.
    assert "sk-ant-" not in s
    # Every credential id is the REPLACE_ME placeholder.
    for n in wf["nodes"]:
        for cred in (n.get("credentials") or {}).values():
            assert cred.get("id") == "REPLACE_ME", f"non-placeholder cred in {n['name']}"
    # Discord webhooks are placeholders only (no real webhook path).
    assert "discord.com/api/webhooks/REPLACE_ME" in s
    import re as _re
    real_hooks = [m for m in _re.findall(r"discord\.com/api/webhooks/([^\"'\\ ]+)", s) if m != "REPLACE_ME"]
    assert real_hooks == [], f"non-placeholder Discord webhook(s): {real_hooks}"


# ---- Live-bug regression (2026-07-15): Build Brake Alert branch-bound accessor ----
#
# A bare $('x').first() binds to ONE statically-resolved output branch of x, chosen by
# walking backwards from the reading node. evaluate's error branch REJOINS the success
# path at nsg_deny, so that walk resolved to branch 1 (the error output), which is empty
# on every successful trip -> first() -> undefined -> .json -> TypeError -> no Discord
# alert on a fired brake. These tests pin the fix's shape. They do NOT execute the JS.

def _brake_alert_js():
    wf = _gen_brake()
    return next(n for n in wf["nodes"] if n["name"] == "Build Brake Alert")["parameters"]["jsCode"]


def _code_only(js):
    """jsCode minus its full-line // comments. These assertions are about what the node
    EXECUTES: the fix's comment block quotes the very `$('evaluate').first().json` pattern
    it removed, so a raw grep would flag that prose as a bug AND let a real one hide behind
    a comment. No string literal in this node starts a line with //, so this is safe."""
    return "\n".join(ln for ln in js.splitlines() if not ln.strip().startswith("//"))


def test_brake_alert_has_no_unguarded_first_json_deref():
    # The exact live crash: `$('evaluate').first().json || {}` derefs .json BEFORE the
    # `|| {}` can apply, so an empty branch throws and the alert is never sent.
    js = _code_only(_brake_alert_js())
    bad = re.findall(r"\$\([^)]*\)\s*\.\s*(?:first|last)\([^)]*\)\s*\.\s*json", js)
    assert bad == [], f"unguarded .first(...).json deref(s) in Build Brake Alert: {bad}"


def test_brake_alert_reads_no_node_by_string_literal():
    # Every node read must go through the guarded helper (which takes the name as a
    # variable), so no read can escape the try/catch. Robust to renaming the helper or
    # its parameter, unlike asserting a specific identifier.
    js = _code_only(_brake_alert_js())
    direct = re.findall(r"\$\(\s*['\"][^'\"]+['\"]\s*\)", js)
    assert direct == [], f"node read(s) outside the guarded helper: {direct}"


def test_brake_alert_pins_an_explicit_branch_index_on_every_accessor():
    # The whole bug is the DEFAULT branch resolution. Every first/last/all call must pass
    # a branch index explicitly; a zero-arg call re-opens the exact live failure.
    js = _code_only(_brake_alert_js())
    zero_arg = re.findall(r"\$\([^)]*\)\s*\.\s*(?:first|last|all)\(\s*\)", js)
    assert zero_arg == [], f"zero-arg (default-branch) accessor(s): {zero_arg}"


def test_brake_alert_probes_both_nsg_deny_branches():
    # Blind defence, NOT a convergence fix, and the distinction matters because it is the exact
    # rule this whole file exists to respect. The branchIndex argument selects the REFERENCED
    # node's own OUTPUT index. nsg_deny has exactly one output (pinned by
    # test_nsg_deny_error_still_reaches_the_alert_on_its_regular_output), so a read of it can
    # only ever resolve to 0 no matter how many nodes feed IN to it. Input convergence is a
    # different thing from output branch index; what made `evaluate` vulnerable was that IT has
    # two outputs. The [0,1] probe is cheap insurance if nsg_deny ever regains a second output.
    js = re.sub(r"\s+", "", _code_only(_brake_alert_js()))
    assert "readJson('nsg_deny',[0,1])" in js, "nsg_deny must be probed on both branch indexes"


def test_brake_alert_reads_the_nsg_fired_flag_not_just_access():
    # /brake/nsg-deny answers 200 with {fired:false,access:""} on brake_not_configured and
    # brake_error. Reading only `access` renders a FAILED authoritative brake as a mild
    # 'unknown'. Assert the property read itself, not the word "fired" (which also appears
    # in prose and in the '**fired**' literal) -- otherwise the test is tautological.
    js = _code_only(_brake_alert_js())
    assert re.search(r"nsg\s*\.\s*fired", js), \
        "must read nsg_deny's `fired` property, not infer success from `access`"
    assert "NOT CONFIRMED" in js, "a non-fired NSG deny must render as a loud failure"


def test_brake_alert_distinguishes_no_verdict_from_reason_unknown():
    # On the fail-closed path evaluate's verdict fields are ABSENT. Rendering that as
    # reason 'unknown' is dishonest on the exact path where the operator most needs to
    # know the evaluator itself broke.
    js = _code_only(_brake_alert_js())
    assert "no verdict" in js and "FAIL-CLOSED" in js


def test_brake_alert_body_is_wrapped_so_it_cannot_throw():
    # Hard operational requirement: a fired brake must always notify. Both the helper and
    # the render body are guarded, and the embed is returned unconditionally.
    js = _code_only(_brake_alert_js())
    assert len(re.findall(r"\bcatch\s*\(", js)) >= 2, \
        "both the node read helper and the render body must be try/catch guarded"
    assert js.rstrip().endswith("return [{ json: { discord_body } }];"), \
        "the embed must be returned unconditionally, outside every try block"


def test_brake_alert_does_not_claim_containment_confirmed():
    # The contain ACTION response never confirms containment status. A10 tightened this:
    # the alert now fires on a branch PARALLEL to contain, so it cannot even claim the
    # action was submitted -- at render time contain has not run yet.
    # _code_only: the comment block quotes the old "action submitted" wording to explain why
    # A10 removed it, and this assertion is about what the node RENDERS, not what it documents.
    js = _code_only(_brake_alert_js())
    assert "does not wait" in js, "the alert must say it does not wait on the contain result"
    for claim in ["containedStatus", "contained successfully", "is contained",
                  "containment confirmed", "action submitted"]:
        assert claim not in js, f"dishonest containment claim: {claim}"


# ---- honeypot-host-feeder (2026-07-15): the FAST feeder, rebuilt as a pull ----------------
# Splunk's built-in webhook alert action cannot deliver the {events, source} contract: its
# envelope is fixed to {result, sid, results_link, search_name, owner, app} and `result` is the
# FIRST result row only. POSTed verbatim to the real app it scored 200 trip:false. So the fast
# feeder pulls: Schedule Trigger -> GET /brake/host-feed -> POST the proven contract. It is a
# SEPARATE workflow on purpose -- a second trigger on honeypot-brake would add a second ancestry
# path through the proven graph, which is the exact bug class that already fired live (b0a68b3).

def _gen_host_feeder():
    subprocess.run([sys.executable, str(_HERE / "build_honeypot_host_feeder_workflow.py")],
                   check=True, cwd=_ROOT)
    return json.loads((_ROOT / "JSON" / "honeypot-host-feeder.json").read_text(encoding="utf-8"))


def _feeder_nodes(wf):
    return {n["name"]: n for n in wf["nodes"] if n["type"] != "n8n-nodes-base.stickyNote"}


def test_host_feeder_is_a_linear_pull_chain():
    wf = _gen_host_feeder()
    conns = wf["connections"]
    assert sorted(_feeder_nodes(wf)) == ["Schedule Trigger", "host_feed", "post_brake"]
    assert conns["Schedule Trigger"]["main"] == [[{"node": "host_feed", "type": "main", "index": 0}]]
    assert conns["host_feed"]["main"] == [[{"node": "post_brake", "type": "main", "index": 0}]]
    assert "post_brake" not in conns, "post_brake is terminal"


def test_host_feeder_polls_every_minute():
    # 1-minute schedule over the SPL's trailing 5-minute window. The overlap is deliberate and
    # harmless: /brake/evaluate is stateless per call, so re-sending the same connections cannot
    # accumulate. It does mean one burst can trip up to 5 times -- the NSG PUT is idempotent
    # (same rule name/priority) and contain is AID-pinned, so that is noise, not damage.
    wf = _gen_host_feeder()
    rule = _feeder_nodes(wf)["Schedule Trigger"]["parameters"]["rule"]
    assert rule["interval"] == [{"field": "minutes", "minutesInterval": 1}]


def test_host_feeder_reads_the_host_feed_endpoint():
    wf = _gen_host_feeder()
    n = _feeder_nodes(wf)["host_feed"]
    assert n["parameters"]["method"] == "GET"
    assert n["parameters"]["url"] == "http://grounding-service:8000/brake/host-feed"


def test_host_feeder_posts_the_proven_brake_contract():
    # Reads $json (its immediate input), NOT $('host_feed').first(). A zero-arg default-branch
    # accessor is what silently bound to an empty error branch in b0a68b3; $json has no branch
    # index to get wrong. host_feed is single-output anyway, so this is belt and braces.
    wf = _gen_host_feeder()
    n = _feeder_nodes(wf)["post_brake"]
    assert n["parameters"]["method"] == "POST"
    assert n["parameters"]["url"] == "http://10.0.0.6:5678/webhook/honeypot-brake"
    # sendBody + specifyBody are what make jsonBody mean anything, and the leading "=" is what
    # makes n8n EVALUATE it rather than POST the literal template text. Drop any of the three and
    # the brake receives a body with no usable events -> Normalize Events coerces to [] -> 200
    # trip:false -> a green, permanently inert fast feeder. Pin the expression byte-exactly.
    assert n["parameters"]["sendBody"] is True
    assert n["parameters"]["specifyBody"] == "json"
    body = n["parameters"]["jsonBody"]
    assert body.startswith("="), "n8n evaluates jsonBody only when it is prefixed '='"
    assert body == "={{ JSON.stringify({ events: $json.events, source: $json.source }) }}"


def test_host_feeder_halts_on_a_feed_error_instead_of_posting():
    # LOAD-BEARING, and the reason this workflow overrides nothing. /brake/host-feed 503s whenever
    # Splunk errors, and n8n's DEFAULT onError is stopWorkflow: the execution goes red and nothing
    # is POSTed. continueRegularOutput would POST a body with events undefined -> JSON.stringify
    # drops the key -> honeypot-brake's Normalize Events coerces it to events:[] -> 200 trip:false
    # -> a GREEN, silently inert feeder. (An earlier version of this comment claimed it would 422
    # into an NSG deny and strangle the box. That was backwards: Normalize Events launders the
    # missing key one hop before Pydantic can reject it.) Red-and-loud beats green-and-blind.
    wf = _gen_host_feeder()
    for name in ("host_feed", "post_brake"):
        n = _feeder_nodes(wf)[name]
        assert n.get("onError") in (None, "stopWorkflow"), (
            f"{name} must halt on error, never continue into a malformed brake POST")


def test_host_feeder_no_live_secret():
    wf = _gen_host_feeder()
    s = json.dumps(wf, ensure_ascii=False)
    assert "sk-ant-" not in s
    assert "discord.com/api/webhooks/" not in s, "the feeder notifies nothing; it has no webhook"
    for n in wf["nodes"]:
        for cred in (n.get("credentials") or {}).values():
            assert cred.get("id") == "REPLACE_ME", f"non-placeholder cred in {n['name']}"


def test_no_code_node_reads_a_converging_multi_output_node_by_default_branch():
    # The generic invariant that would have caught b0a68b3 the day it landed: if BOTH
    # branches of a multi-output node reach the same Code node, that Code node cannot read
    # it with a default-branch accessor -- one run type always sees an empty branch.
    # Convergence, not multi-output-ness, is the distinguishing property (falcon-contain's
    # contain_guard is two-output but its error branch dead-ends, so it is safe).
    # Every workflow we generate belongs here. This list was hardcoded to three and
    # falcon-alert-poller.json was silently outside it -- a registration gap that defeats the
    # invariant exactly when a NEW workflow lands, which is when it matters most. Both it and
    # honeypot-host-feeder are now covered. Add any future workflow to this tuple.
    for wf in (_gen_brake(),
               _gen_host_feeder(),
               json.loads((_ROOT / "JSON" / "honeypot-triage.json").read_text(encoding="utf-8")),
               json.loads((_ROOT / "JSON" / "falcon-contain.json").read_text(encoding="utf-8")),
               json.loads((_ROOT / "JSON" / "falcon-alert-poller.json").read_text(encoding="utf-8"))):
        conns = wf["connections"]
        code_nodes = {n["name"]: n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.code"}

        def reachable(start):
            seen, stack = {start}, [start]
            while stack:
                for branch in conns.get(stack.pop(), {}).get("main", []):
                    for c in branch:
                        if c["node"] not in seen:
                            seen.add(c["node"])
                            stack.append(c["node"])
            return seen

        offenders = []
        for src, c in conns.items():
            outs = [b for b in c.get("main", [])]
            if len(outs) < 2 or not all(outs):
                continue
            common = set.intersection(*[
                set.union(*[reachable(x["node"]) for x in br]) for br in outs])
            for name in sorted(common & set(code_nodes)):
                js = _code_only(code_nodes[name]["parameters"]["jsCode"])
                if re.search(r"\$\(\s*['\"]%s['\"]\s*\)\s*\.\s*(?:first|last|all)\(\s*\)"
                             % re.escape(src), js):
                    offenders.append((wf["name"], name, src))
        assert offenders == [], (
            "Code node(s) read a multi-output node with a default-branch accessor even "
            f"though BOTH of its branches converge on them: {offenders}")


# ---- Task A10 (2026-07-15): the alert must not depend on the Falcon path ----
# The live dry-run proved both brake layers fire, but Discord never arrived. Fixing the
# Build Brake Alert accessor was necessary and not sufficient: the alert still sat at the
# END of nsg_deny -> resolve_host -> contain_guard -> contain, and n8n's default onError is
# stopWorkflow, so ANY throw on that chain kills the alert AFTER the NSG has already flipped.
# That is the one outcome this workflow may never produce: a braked, contained box and a
# sleeping operator. It also had a date on it -- once the Falcon trial lapses (2026-07-28),
# resolve_host/contain start failing auth and silent-brake becomes the DEFAULT, not an edge
# case. A10 hangs the alert directly off nsg_deny (the authoritative brake) and makes every
# node on the fire path non-halting.

_FIRE_PATH = ("nsg_deny", "resolve_host", "contain_guard", "contain",
              "Build Brake Alert", "Discord BRAKE FIRED")


def test_alert_hangs_directly_off_the_authoritative_nsg_deny():
    wf = _gen_brake()
    targets = [c["node"] for c in wf["connections"]["nsg_deny"]["main"][0]]
    assert "Build Brake Alert" in targets, "the alert must fire straight off the NSG deny"


def test_alert_fires_before_the_falcon_chain_is_attempted():
    # CANVAS POSITION is the real mechanism, not connection list order. n8n 2.21.7
    # workflow-execute.ts:2072-2085 re-sorts a fan-out by position under the literal comment
    # "Always execute the node that is more to the top-left first"; list order survives only as
    # a stable tiebreak on identical [x,y]. So the invariant that actually decides who runs
    # first is the LAYOUT: the alert must sit above the Falcon chain. Reviewers proved the
    # point by moving the alert to y=400, which inverts the true order while a list-order
    # assertion stayed green. This matters beyond latency: resolve_host/contain carry no
    # timeout (n8n default ~300s), so a wrong layout after the Falcon trial lapses could stall
    # the notification for minutes.
    wf = _gen_brake()
    pos = {n["name"]: n["position"] for n in wf["nodes"]}
    assert pos["Build Brake Alert"][1] < pos["resolve_host"][1], \
        "v1 sorts a fan-out top-left-first: the alert must sit ABOVE resolve_host"
    # Belt-and-braces, and the tiebreak if the two ever share a position.
    targets = [c["node"] for c in wf["connections"]["nsg_deny"]["main"][0]]
    assert targets[0] == "Build Brake Alert", f"alert must be first in the fan-out, got {targets}"


def test_alert_delivery_never_halts_the_falcon_contain():
    # A10 regression caught in review. v1 is depth-first, so the proven order is
    # nsg_deny -> Build Brake Alert -> Discord BRAKE FIRED -> resolve_host -> ... -> contain.
    # That puts Discord AHEAD of the Falcon chain, and a node with the default
    # onError=stopWorkflow halts the whole run on a 429/5xx -- so a rate-limited Discord would
    # mean the box never gets contained. Both feeders POST to this one workflow, so concurrent
    # brakes hammering a single rate-limited webhook is exactly the storm case. Discord is
    # terminal, so continuing on error costs nothing.
    wf = _gen_brake()
    d = next(n for n in wf["nodes"] if n["name"] == "Discord BRAKE FIRED")
    assert d.get("onError") == "continueRegularOutput", \
        "a Discord failure must not swallow the Falcon contain that runs after it"
    assert d.get("retryOnFail") is True, "the last link in the must-be-sent chain needs a retry"
    assert d.get("maxTries", 0) >= 2


def test_no_falcon_node_can_reach_the_alert():
    # The whole point of A10: nothing on the Falcon chain is upstream of the alert, so no
    # Falcon failure (expired trial, 429, 5xx) can swallow the notification.
    wf = _gen_brake()
    for name in ("resolve_host", "contain_guard", "contain"):
        for branch in wf["connections"].get(name, {}).get("main", []):
            for c in (branch or []):
                assert c["node"] != "Build Brake Alert", f"{name} still feeds the alert"


def test_no_node_on_the_fire_path_halts_the_workflow():
    # Default onError is stopWorkflow. A throw in any of these kills the sibling alert branch
    # too. contain_guard legitimately uses continueErrorOutput (its 409 routes to REFUSED);
    # the rest continue on their regular output. Either way: non-halting.
    wf = _gen_brake()
    for name in _FIRE_PATH:
        n = next(x for x in wf["nodes"] if x["name"] == name)
        assert n.get("onError") in ("continueRegularOutput", "continueErrorOutput"), \
            f"{name} halts the workflow on error, which would swallow the brake alert"


def test_brake_alert_reads_the_evaluate_verdict_from_branch_zero():
    # The exact index at the heart of the live bug, and it was unguarded until review: a
    # reviewer mutated readJson('evaluate', [0]) -> [1] and all 42 tests still passed, while
    # every REAL trip would render "no verdict / FAIL-CLOSED" and suppress the reason,
    # distinct_dst and conn_count. Same inverted-polarity lie as the original crash, except it
    # does not throw, so nothing else would ever notice.
    js = re.sub(r"\s+", "", _code_only(_brake_alert_js()))
    assert "readJson('evaluate',[0])" in js, \
        "the verdict lives on evaluate output 0; output 1 is the fail-closed error item"


def test_every_code_node_parses():
    # The suite asserts on the jsCode STRING and never runs it, so an unbalanced brace shipped
    # green: a Code node that cannot parse emits nothing, which IS the silent-brake outcome
    # this workflow may never produce. Cheapest possible gate against that whole class.
    node_bin = shutil.which("node")
    if not node_bin:
        pytest.skip("node not on PATH")
    wf = _gen_brake()
    for n in wf["nodes"]:
        js = n.get("parameters", {}).get("jsCode")
        if not js:
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(js)
            tmp = fh.name
        try:
            r = subprocess.run([node_bin, "--check", tmp], capture_output=True, text=True)
            assert r.returncode == 0, f"{n['name']} jsCode does not parse: {r.stderr}"
        finally:
            os.unlink(tmp)


def test_nsg_deny_error_still_reaches_the_alert_on_its_regular_output():
    # nsg_deny must NOT use continueErrorOutput: a second output that rejoins the alert's
    # ancestry is exactly the convergence trap that caused the live bug. continueRegularOutput
    # keeps one output, so an nsg_deny failure still flows to the alert, which then renders
    # NOT CONFIRMED instead of going quiet.
    wf = _gen_brake()
    nsg = next(x for x in wf["nodes"] if x["name"] == "nsg_deny")
    assert nsg.get("onError") == "continueRegularOutput"
    assert len(wf["connections"]["nsg_deny"]["main"]) == 1, "nsg_deny must stay single-output"


# ---- Task A8: honeypot-brake-triggers.md (SPL + KQL + the successful-logon alert) ----

def test_brake_triggers_doc_has_all_three_queries():
    doc = (_HERE / "honeypot-brake-triggers.md").read_text(encoding="utf-8")
    assert "EventCode=3" in doc or "Sysmon" in doc          # host trigger (EID 3)
    # The doc must name the sourcetype that actually matches. splunk-inputs.conf sets renderXml=1,
    # so Sysmon lands under XmlWinEventLog -- a string with no "Sysmon" substring in it. The doc
    # carried `sourcetype=*Sysmon*` from d39a1c4 until 2026-07-15 and it matched ZERO events for
    # two sessions (live receipts, 24h: *Sysmon* -> 0; XmlWinEventLog EventCode=3 -> 15,935).
    # Note the assert above cannot catch that regression: it passes on the mere word "Sysmon".
    assert "XmlWinEventLog" in doc
    # Network trigger: VNet flow logs + Traffic Analytics land in NTANetAnalytics. Verified live
    # 2026-07-15: AzureNetworkAnalytics_CL (the legacy NSG-flow-log table) does not exist in the
    # workspace at all and never will, since Azure retired new NSG-flow-log creation. Assert the
    # table we actually query, or this passes on the mere mention of the dead one.
    assert "NTANetAnalytics" in doc
    assert "DestPublicIps" in doc                           # DestIp is empty on every outbound flow
    assert "4624" in doc and "Logon_Type=10" in doc.replace(" ", "").replace("logon_type", "Logon_Type")
    assert "/honeypot-brake" in doc                         # feeders POST to the brake webhook
