from detection_authoring.compile import compile_spl, parse_errors

GOOD = """
title: PS Encoded
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -EncodedCommand '
  condition: selection
"""

MALFORMED = "title: x\ndetection: {condition: sel}\n"  # references undefined selection


def test_good_rule_has_no_parse_errors():
    assert parse_errors(GOOD) == []


def test_good_rule_compiles_to_spl():
    spl = compile_spl(GOOD)
    assert spl is not None
    assert "powershell.exe" in spl.lower()


def test_malformed_rule_reports_parse_errors():
    assert parse_errors(MALFORMED) != []
