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


# Task 2 review follow-up: cover the three guard branches the brief's tests missed
# (wrong logsource.product, non-string condition, unmatched condition token).
BAD_PRODUCT = """
title: x
logsource: {product: linux, category: process_creation}
detection: {sel: {Image: 'x'}, condition: sel}
"""

NON_STRING_CONDITION = """
title: x
logsource: {product: windows, category: process_creation}
detection: {sel: {Image: 'x'}, condition: [sel]}
"""

UNKNOWN_TOKEN = """
title: x
logsource: {product: windows, category: process_creation}
detection: {sel: {Image: 'x'}, condition: sel and ghost}
"""


def test_wrong_product_flagged():
    out = check_supported(yaml.safe_load(BAD_PRODUCT))
    assert any("product" in f for f in out)


def test_non_string_condition_flagged():
    out = check_supported(yaml.safe_load(NON_STRING_CONDITION))
    assert any("condition" in f for f in out)


def test_unknown_condition_token_flagged():
    out = check_supported(yaml.safe_load(UNKNOWN_TOKEN))
    assert any("ghost" in f for f in out)


# Task 4 review follow-up: a detection with zero selections makes "all of them"
# vacuously match everything (all([]) is True). The guard must reject it.
NO_SELECTIONS = """
title: x
logsource: {product: windows, category: process_creation}
detection: {condition: all of them}
"""


def test_detection_with_no_selections_flagged():
    out = check_supported(yaml.safe_load(NO_SELECTIONS))
    assert any("no selections" in f for f in out)
