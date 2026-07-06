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
