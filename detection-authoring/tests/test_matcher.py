from detection_authoring.matcher import matches, selection_matches

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


# Task 3 review follow-up: regression-guard the |re case-sensitivity semantics
# and cover the startswith modifier branch.
def test_regex_is_case_sensitive_without_inline_flag():
    # Bare |re is case-sensitive: a lowercase pattern must NOT match "-E " in
    # PS_EVENT. Guards against a future re.IGNORECASE regression in _match_scalar.
    assert not selection_matches({"CommandLine|re": r"-e[nc]* "}, PS_EVENT)


def test_startswith_case_insensitive():
    assert selection_matches({"CommandLine|startswith": "PowerShell.EXE"}, PS_EVENT)


DET = {
    "selection": {"Image|endswith": "\\powershell.exe"},
    "filter": {"ParentImage|endswith": "\\explorer.exe"},
    "condition": "selection and not filter",
}


def test_and_not_true_when_filter_absent():
    ev = {"Image": "x\\powershell.exe", "ParentImage": "x\\WmiPrvSE.exe"}
    assert matches(DET, ev)


def test_and_not_false_when_filter_present():
    ev = {"Image": "x\\powershell.exe", "ParentImage": "x\\explorer.exe"}
    assert not matches(DET, ev)


def test_one_of_pattern():
    det = {
        "sel_ip": {"CommandLine|re": r"\b\d{1,3}(\.\d{1,3}){3}\b"},
        "sel_url": {"CommandLine|contains": "http://"},
        "condition": "1 of sel_*",
    }
    assert matches(det, {"CommandLine": "cmd /c curl http://evil"})
    assert not matches(det, {"CommandLine": "cmd /c dir"})


def test_all_of_them():
    det = {
        "a": {"Image|endswith": "\\cmd.exe"},
        "b": {"CommandLine|contains": "/c"},
        "condition": "all of them",
    }
    assert matches(det, {"Image": "x\\cmd.exe", "CommandLine": "cmd /c dir"})
    assert not matches(det, {"Image": "x\\cmd.exe", "CommandLine": "cmd /k dir"})
