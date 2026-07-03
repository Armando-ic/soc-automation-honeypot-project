from red_team.report import build_baseline_report
from red_team.runner import CaseResult, TrialRecord
from red_team.scorer import TrialScore
from red_team.cases import AttackCase
from red_team.harness.model_client import Outcome


def _case(cid, cls, wc, expected_correct=None):
    return AttackCase(id=cid, class_=cls, atlas="", source="splunk", alert={}, fixed_enrichment={},
                      retrieval="real", fixed_techniques=None, objective="",
                      expected_correct=expected_correct or {"severity": "high"}, win_condition=wc)


def _trial(dev, byp, invalid=False, raw_severity="medium", outcome=None):
    return TrialRecord(outcome=outcome, verify_body={}, passed=byp,
                       score=TrialScore(deviated=dev, bypassed=byp, matched=[], invalid=invalid, invalid_reason=""),
                       raw_severity=raw_severity)


def test_report_has_per_class_rows_cis_and_open_label():
    a2 = CaseResult(case=_case("A2-x", "LLM01", ["malicious_ioc_marked_clean"]),
                    trials=[_trial(True, True) for _ in range(50)], k=50)
    a3 = CaseResult(case=_case("A3-x", "LLM01", ["cites_technique_not_in_retrieved"]),
                    trials=[_trial(False, False) for _ in range(50)], k=50)
    md = build_baseline_report([a2, a3])
    assert "A2" in md and "A3" in md
    assert "95% CI" in md
    assert "OPEN" in md                              # A2 labeled OPEN
    assert "claude-opus-4-8" in md and "MAX_TOKENS" in md


def test_a3_is_not_labeled_open():
    """A3's predicate (cites_technique_not_in_retrieved) maps to a real verifier
    check (mitre_in_retrieved) in PREDICATE_GUARD, so A3 must NOT be marked OPEN."""
    a2 = CaseResult(case=_case("A2-x", "LLM01", ["malicious_ioc_marked_clean"]),
                    trials=[_trial(True, True) for _ in range(50)], k=50)
    a3 = CaseResult(case=_case("A3-x", "LLM01", ["cites_technique_not_in_retrieved"]),
                    trials=[_trial(False, False) for _ in range(50)], k=50)
    md = build_baseline_report([a2, a3])
    # Isolate the A3 section (everything after the "## A3" heading up to the
    # next "## " heading) and confirm no OPEN marker appears inside it.
    a3_start = md.index("## A3")
    rest = md[a3_start:]
    next_heading = rest.find("\n## ", 1)
    a3_section = rest if next_heading == -1 else rest[:next_heading]
    assert "OPEN" not in a3_section


def test_a1_severity_distribution_is_rendered():
    trials = (
        [_trial(True, False, raw_severity="medium") for _ in range(3)]
        + [_trial(False, False, raw_severity="high") for _ in range(2)]
    )
    a1 = CaseResult(case=_case("A1-x", "LLM01", ["severity_below_expected"]), trials=trials, k=5)
    md = build_baseline_report([a1])
    a1_start = md.index("## A1")
    rest = md[a1_start:]
    next_heading = rest.find("\n## ", 1)
    a1_section = rest if next_heading == -1 else rest[:next_heading]
    assert "medium" in a1_section and "high" in a1_section
    assert "3" in a1_section and "2" in a1_section


def test_zero_rate_reports_upper_bound_not_bare_zero_percent():
    """k_byp == 0 over n>0 valid trials must render an upper-bound CI, not a
    bare standalone '0%'."""
    trials = [_trial(False, False) for _ in range(20)]
    b1 = CaseResult(case=_case("B1-x", "LLM01", ["contain_suppressed"],
                                expected_correct={"contain_expected": True}),
                    trials=trials, k=20)
    md = build_baseline_report([b1])
    b1_start = md.index("## B1")
    rest = md[b1_start:]
    next_heading = rest.find("\n## ", 1)
    b1_section = rest if next_heading == -1 else rest[:next_heading]
    assert "upper 95% bound" in b1_section
    import re
    # No bare standalone "0%" token anywhere in the class section (a preceding
    # digit like "20%" or "0/20" is fine -- only an isolated "0%" is banned).
    assert re.search(r"(?<![\d.])0%", b1_section) is None


def test_invalid_trials_excluded_from_denominator():
    """A CaseResult mixing valid + invalid trials must exclude the invalid one
    from n, and must separately report the invalid count."""
    trials = [_trial(True, True) for _ in range(4)] + [_trial(False, False, invalid=True)]
    c1 = CaseResult(case=_case("C1-x", "LLM01", ["notes_leak_prompt"]), trials=trials, k=5)
    md = build_baseline_report([c1])
    c1_start = md.index("## C1")
    rest = md[c1_start:]
    next_heading = rest.find("\n## ", 1)
    c1_section = rest if next_heading == -1 else rest[:next_heading]
    # n=4 valid trials, k_dev=4/4, k_byp=4/4 -- the denominator must be 4, not 5.
    assert "4/4" in c1_section
    assert "5/5" not in c1_section
    # The single invalid trial must be reported.
    assert "1" in c1_section and "invalid" in c1_section.lower()


def test_outcome_distribution_tolerates_none_and_is_reported_separately():
    """outcome=None must not crash; the outcome distribution (including a mix
    of enum members and None) is reported per class, separate from the rates."""
    trials = [
        _trial(True, True, outcome=Outcome.TOOL_CALL),
        _trial(False, False, outcome=Outcome.REFUSAL),
        _trial(False, False, outcome=None),
    ]
    d1 = CaseResult(case=_case("D1-x", "LLM01", ["output_contains_discord_mention"]), trials=trials, k=3)
    md = build_baseline_report([d1])  # must not raise
    d1_start = md.index("## D1")
    rest = md[d1_start:]
    next_heading = rest.find("\n## ", 1)
    d1_section = rest if next_heading == -1 else rest[:next_heading]
    assert "tool_call" in d1_section.lower()
    assert "refusal" in d1_section.lower()


def test_header_records_model_max_tokens_commit_and_k():
    a2 = CaseResult(case=_case("A2-x", "LLM01", ["malicious_ioc_marked_clean"]),
                    trials=[_trial(True, True) for _ in range(10)], k=10)
    md = build_baseline_report([a2])
    assert "claude-opus-4-8" in md
    assert "MAX_TOKENS" in md
    assert "4096" in md
    assert "no sampling" in md.lower() or "no temperature" in md.lower()
    assert "10" in md  # K appears somewhere in the header/class row


def test_multi_case_class_k_header_shows_per_case_k_not_class_total():
    """I6: a class with >=2 cases each at K=50 must render the per-case K (50) in
    the 'K (trials/case)' header, NOT the class total (100 = sum of per-case K)."""
    c1 = CaseResult(case=_case("A3-x", "LLM01", ["cites_technique_not_in_retrieved"]),
                    trials=[_trial(False, False) for _ in range(50)], k=50)
    c2 = CaseResult(case=_case("A3-y", "LLM01", ["cites_technique_not_in_retrieved"]),
                    trials=[_trial(False, False) for _ in range(50)], k=50)
    md = build_baseline_report([c1, c2])
    a3_start = md.index("## A3")
    rest = md[a3_start:]
    next_heading = rest.find("\n## ", 1)
    a3_section = rest if next_heading == -1 else rest[:next_heading]
    assert "K (trials/case): 50" in a3_section
    # The mislabeled class total must NOT appear as the per-case K value.
    assert "K (trials/case): 100" not in a3_section
    # Sanity: 2 cases, 100 total trials.
    assert "Cases: 2" in a3_section
    assert "Total trials: 100" in a3_section


def test_varying_k_class_header_shows_distinct_set():
    """I6: if per-case K varies within a class, the header renders the sorted
    distinct set rather than a single (wrong) number."""
    c1 = CaseResult(case=_case("A3-x", "LLM01", ["cites_technique_not_in_retrieved"]),
                    trials=[_trial(False, False) for _ in range(50)], k=50)
    c2 = CaseResult(case=_case("A3-y", "LLM01", ["cites_technique_not_in_retrieved"]),
                    trials=[_trial(False, False) for _ in range(10)], k=10)
    md = build_baseline_report([c1, c2])
    a3_start = md.index("## A3")
    rest = md[a3_start:]
    next_heading = rest.find("\n## ", 1)
    a3_section = rest if next_heading == -1 else rest[:next_heading]
    assert "K (trials/case): [10, 50]" in a3_section


def test_zero_valid_trials_does_not_raise_zero_division():
    """A class whose trials are ALL invalid has n==0 -- must not divide by
    zero, and must render an n/a-style message instead."""
    trials = [_trial(False, False, invalid=True) for _ in range(3)]
    e1 = CaseResult(case=_case("E1-x", "LLM01", ["ioc_variant_passes"],
                                expected_correct={"canonical_iocs": ["evil.com"]}),
                    trials=trials, k=3)
    md = build_baseline_report([e1])  # must not raise ZeroDivisionError
    assert "E1" in md
