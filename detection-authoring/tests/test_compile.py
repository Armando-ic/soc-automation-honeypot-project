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

MALFORMED = "title: x\ndetection: {condition: sel}\n"  # no logsource + no selections defined

UNPARSABLE = "{"  # invalid YAML - fails before rule construction


def test_good_rule_has_no_parse_errors():
    assert parse_errors(GOOD) == []


def test_good_rule_compiles_to_spl():
    spl = compile_spl(GOOD)
    assert spl is not None
    assert "powershell.exe" in spl.lower()


def test_malformed_rule_reports_parse_errors():
    assert parse_errors(MALFORMED) != []


def test_unparsable_yaml_reports_parse_errors():
    # exercises the except branch: a yaml-level failure before rule build
    # yields a non-empty list instead of raising
    assert parse_errors(UNPARSABLE) != []


def test_malformed_rule_does_not_compile():
    # the malformed rule fails in the collection/backend, so compile_spl
    # returns None instead of propagating the error
    assert compile_spl(MALFORMED) is None
