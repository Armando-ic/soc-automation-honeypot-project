from detection_authoring.gate import run_gate

TIGHT_001 = """
title: PowerShell EncodedCommand
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|re: '(?i)\\s-e(nc(odedcommand)?)?\\s'
  condition: selection
"""

BROAD = """
title: Any PowerShell
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
"""

WRONG_FIELD_VALUE = """
title: Nope
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\notepad.exe'
  condition: selection
"""

UNSUPPORTED = """
title: Bad
logsource: {product: windows, category: process_creation}
detection:
  selection:
    CommandLine|base64offset|contains: 'x'
  condition: selection
"""


def test_tight_rule_passes_all_four():
    r = run_gate(TIGHT_001, "T1059.001")
    assert r.t1_parse_ok and r.subset_ok and r.t2_compile_ok and r.t3_tp_ok and r.t4_tn_ok
    assert r.passed


def test_broad_rule_fails_t4_on_benign_powershell():
    r = run_gate(BROAD, "T1059.001")
    assert r.t3_tp_ok       # it does fire on the positives
    assert not r.t4_tn_ok   # but also fires on benign -File update.ps1
    assert not r.passed
    assert r.benign_false_positives


def test_wrong_value_fails_t3():
    r = run_gate(WRONG_FIELD_VALUE, "T1059.001")
    assert not r.t3_tp_ok
    assert not r.passed


def test_unsupported_feature_fails_subset_and_skips_behavioral():
    r = run_gate(UNSUPPORTED, "T1059.001")
    assert not r.subset_ok
    assert not r.passed


def test_non_mapping_yaml_fails_gracefully():
    # untrusted drafter text can parse to a non-mapping (scalar or list);
    # the gate must return a failing verdict, not raise
    for bad in ("just a scalar string", "- 1\n- 2\n"):
        r = run_gate(bad, "T1059.001")
        assert not r.passed
        assert r.unsupported  # flagged out-of-subset, not crashed


def test_malformed_inner_structure_fails_gracefully():
    # top-level is a mapping, but logsource/detection (or a selection key) is
    # itself malformed. The gate must still return a failing verdict, not raise
    # an AttributeError out of check_supported.
    bad_rules = (
        "logsource: [a, b]\ndetection: {selection: {Image: x}, condition: selection}\n",
        "logsource: {product: windows, category: process_creation}\ndetection: [1, 2, 3]\n",
        "logsource: {product: windows, category: process_creation}\ndetection: {selection: {1: x}, condition: selection}\n",
    )
    for bad in bad_rules:
        r = run_gate(bad, "T1059.001")
        assert not r.passed
        assert r.unsupported  # routed to a failing verdict, not crashed


def test_uneval_condition_fails_gracefully():
    # A bare wildcard selection reference with no `1 of`/`all of` quantifier
    # slips past pySigma (T1) and the subset guard, but the matcher can't
    # resolve the raw token 'selection1*'. run_gate must route that to a failing
    # verdict, not raise a KeyError out of the matcher.
    rule = (
        "title: Bad\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n"
        "  selection1:\n"
        "    Image|endswith: '\\notepad.exe'\n"
        "  condition: selection1*\n"
    )
    r = run_gate(rule, "T1059.001")
    assert not r.passed
    assert not r.subset_ok
    assert r.unsupported


def test_pathological_nesting_is_rejected_not_crashed():
    # Deeply-nested YAML can exhaust the parser stack: a pure-Python
    # RecursionError, or worse a native libyaml C-stack overflow that kills the
    # whole process (no catchable exception). run_gate must reject such input up
    # front and return a failing verdict, never raise. Depth 1200 sits in the
    # RecursionError band but well below the native-crash threshold, so it is
    # safe to exercise here.
    deep = "a: " + "[" * 1200 + "1" + "]" * 1200
    r = run_gate(deep, "T1059.001")
    assert not r.passed
    assert r.unsupported


def test_pathological_block_sequence_is_rejected():
    # The same deep-nesting crash is reachable via YAML block/compact sequence
    # syntax, which uses zero bracket characters, so a bracket char-scan misses
    # it. The guard measures nesting from the event stream instead. ~2700 levels
    # is past the native libyaml crash threshold, so this must be rejected by the
    # guard's crash-safe pure-Python event scan before parse_errors ever runs.
    deep = "- " * 2700 + "1"
    r = run_gate(deep, "T1059.001")
    assert not r.passed
    assert r.unsupported
