from detection_authoring.matcher import selection_matches

PS_EVENT = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoProfile -E VwByAGkAdABl",
    "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
}


def test_endswith_case_insensitive():
    assert selection_matches({"Image|endswith": "\\PowerShell.exe"}, PS_EVENT)


def test_contains_list_is_or():
    sel = {"CommandLine|contains": [" -enc ", " -E "]}
    assert selection_matches(sel, PS_EVENT)


def test_contains_all_requires_every_value():
    sel = {"CommandLine|contains|all": ["powershell", " -E "]}
    assert selection_matches(sel, PS_EVENT)
    sel_fail = {"CommandLine|contains|all": ["powershell", "notpresent"]}
    assert not selection_matches(sel_fail, PS_EVENT)


def test_wildcard_equals():
    assert selection_matches({"Image": "*\\powershell.exe"}, PS_EVENT)


def test_regex_modifier():
    assert selection_matches({"CommandLine|re": r"(?i)-e[nc]* "}, PS_EVENT)


def test_missing_field_does_not_match():
    assert not selection_matches({"User": "admin"}, PS_EVENT)


def test_and_across_fields():
    sel = {"Image|endswith": "\\powershell.exe", "ParentImage|endswith": "\\WmiPrvSE.exe"}
    assert selection_matches(sel, PS_EVENT)
