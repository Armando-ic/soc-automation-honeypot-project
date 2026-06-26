from triage_verifier.normalizer import normalize_triage_result


def test_missing_iocs_buckets_filled():
    norm, events = normalize_triage_result({"iocs": {"ips": ["1.2.3.4"]}})
    assert norm["iocs"]["domains"] == []
    assert norm["iocs"]["file_hashes"] == []
    assert any(e["field"] == "iocs.domains" for e in events)


def test_missing_arrays_become_lists():
    norm, events = normalize_triage_result({})
    assert norm["mitre_techniques"] == []
    assert norm["iocs_enriched"] == []
    assert norm["recommended_actions"] == []


def test_scalar_coerced_to_list():
    norm, events = normalize_triage_result({"mitre_techniques": {"id": "T1059.001"}})
    assert norm["mitre_techniques"] == [{"id": "T1059.001"}]
    assert any(e["field"] == "mitre_techniques" for e in events)


def test_clean_input_no_repairs():
    raw = {"iocs": {"ips": [], "domains": [], "file_hashes": [], "users": [], "hosts": []},
           "mitre_techniques": [], "iocs_enriched": [], "recommended_actions": []}
    norm, events = normalize_triage_result(raw)
    assert events == []
