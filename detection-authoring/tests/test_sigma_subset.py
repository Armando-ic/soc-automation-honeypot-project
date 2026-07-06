import yaml

from detection_authoring.sigma_subset import check_supported

GOOD = """
title: PowerShell EncodedCommand
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: [' -enc ', ' -EncodedCommand ']
  condition: selection
"""

BAD_CATEGORY = """
title: x
logsource: {product: windows, category: network_connection}
detection: {sel: {DestinationPort: 4444}, condition: sel}
"""

BAD_MODIFIER = """
title: x
logsource: {product: windows, category: process_creation}
detection: {sel: {CommandLine|base64offset|contains: 'x'}, condition: sel}
"""

BAD_FIELD = """
title: x
logsource: {product: windows, category: process_creation}
detection: {sel: {TotallyMadeUpField: 'x'}, condition: sel}
"""


def test_good_rule_is_supported():
    assert check_supported(yaml.safe_load(GOOD)) == []


def test_wrong_category_flagged():
    out = check_supported(yaml.safe_load(BAD_CATEGORY))
    assert any("category" in f for f in out)


def test_unknown_modifier_flagged():
    out = check_supported(yaml.safe_load(BAD_MODIFIER))
    assert any("base64offset" in f for f in out)


def test_unknown_field_flagged():
    out = check_supported(yaml.safe_load(BAD_FIELD))
    assert any("TotallyMadeUpField" in f for f in out)
