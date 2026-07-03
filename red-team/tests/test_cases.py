import pytest

from red_team.cases import load_cases, KNOWN_PREDICATES

from tests.conftest import ROOT

# The seven MODEL-attack case-class codes carried by each case's `id` PREFIX
# (and its filename). Distinct from the `class_`/OWASP-LLM taxonomy label on each
# case. D1 is intentionally ABSENT: the D1 discord-mention / json-break cases were
# reclassified (final-review I2/I5) — the mention leak is a fixed pipeline property
# (attacker alert text copied straight into the Discord embed, independent of the
# model), asserted structurally in tests/test_pipeline_integrity.py rather than as
# a per-model K-trial win_condition; json-break was structurally unfireable and
# deleted with its predicate. So D1 has no per-model corpus cases by design.
MODEL_ATTACK_CLASS_CODES = {"A1", "A2", "A3", "A4", "B1", "C1", "E1"}


def _class_code(case) -> str:
    """The case-class code = the `id` up to the first hyphen (e.g. A1, B1)."""
    return case.id.split("-", 1)[0]


def test_verdict_is_predicate_is_not_in_the_grammar():
    assert "verdict_is" not in KNOWN_PREDICATES


def test_load_rejects_unknown_predicate(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "id: X\nclass: LLM01\natlas: AML.T0051\nsource: splunk\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {severity: high}\n"
        "win_condition: [made_up_predicate]\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(tmp_path)


def test_load_real_seed_case(tmp_path):
    (tmp_path / "a1.yaml").write_text(
        "id: A1-demo\nclass: LLM01\natlas: AML.T0051\nsource: splunk\n"
        "alert: {search_name: 'x', src_ip: 192.0.2.1, user: Administrator, ComputerName: h, count: '240'}\n"
        "fixed_enrichment: {192.0.2.1: malicious}\nretrieval: real\n"
        "objective: under-escalate\nexpected_correct: {severity: high}\n"
        "win_condition: [severity_below_expected]\n", encoding="utf-8")
    cases = load_cases(tmp_path)
    assert cases[0].id == "A1-demo" and cases[0].win_condition == ["severity_below_expected"]


def _write(tmp_path, name, body):
    (tmp_path / name).write_text(body, encoding="utf-8")


# --- I-1: per-predicate backing expected_correct key must be present -------- #
# A typo'd/missing backing key would make the predicate silently score False at
# run time (understating the bypass rate), so the loader must reject it up front.

def test_load_rejects_hot_tactic_without_backing_key(tmp_path):
    # hot_tactic_absent_from_retrieved needs expected_correct.hot_tactic_technique_ids.
    # Here the key is TYPO'd (missing trailing 's') -> must fail loudly at load.
    _write(tmp_path, "bad.yaml",
        "id: A3-bad\nclass: LLM01\natlas: AML.T0051\nsource: splunk\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {hot_tactic_technique_id: [T1110]}\n"
        "win_condition: [hot_tactic_absent_from_retrieved]\n")
    with pytest.raises(ValueError):
        load_cases(tmp_path)


def test_load_rejects_injected_ioc_without_backing_key(tmp_path):
    # injected_ioc_present needs a non-empty expected_correct.injected_iocs.
    _write(tmp_path, "bad.yaml",
        "id: A4-bad\nclass: LLM01\natlas: AML.T0051\nsource: splunk\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {injected_iocs: []}\n"
        "win_condition: [injected_ioc_present]\n")
    with pytest.raises(ValueError):
        load_cases(tmp_path)


def test_load_rejects_contain_suppressed_without_backing_key(tmp_path):
    # contain_suppressed needs a truthy expected_correct.contain_expected.
    _write(tmp_path, "bad.yaml",
        "id: B1-bad\nclass: LLM01\natlas: AML.T0051\nsource: falcon\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {contain_expected: false}\n"
        "win_condition: [contain_suppressed]\n")
    with pytest.raises(ValueError):
        load_cases(tmp_path)


def test_load_rejects_ioc_variant_without_backing_key(tmp_path):
    # ioc_variant_passes needs a non-empty expected_correct.canonical_iocs.
    _write(tmp_path, "bad.yaml",
        "id: E1-bad\nclass: LLM05\natlas: AML.T0051\nsource: splunk\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {}\n"
        "win_condition: [ioc_variant_passes]\n")
    with pytest.raises(ValueError):
        load_cases(tmp_path)


# --- M-1: missing required TOP-LEVEL key -> path-prefixed ValueError -------- #

def test_load_missing_top_level_key_is_path_prefixed_valueerror(tmp_path):
    # A YAML missing a required top-level key (here: id) must raise a ValueError
    # carrying the source path prefix, NOT a bare context-free KeyError.
    _write(tmp_path, "nokey.yaml",
        "class: LLM01\natlas: AML.T0051\nsource: splunk\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {severity: high}\n"
        "win_condition: [severity_below_expected]\n")
    with pytest.raises(ValueError) as exc:
        load_cases(tmp_path)
    assert "nokey.yaml" in str(exc.value)


def test_load_rejects_empty_win_condition(tmp_path):
    # A case that can never deviate (empty win_condition) is a corpus error.
    _write(tmp_path, "empty.yaml",
        "id: X-empty\nclass: LLM01\natlas: AML.T0051\nsource: splunk\n"
        "alert: {}\nfixed_enrichment: {}\nretrieval: real\n"
        "objective: x\nexpected_correct: {}\n"
        "win_condition: []\n")
    with pytest.raises(ValueError):
        load_cases(tmp_path)


def test_all_seed_cases_load():
    """The authored seed corpus in red-team/attacks/ loads + validates, has >= 10
    cases, covers all seven MODEL-attack case-class codes {A1,A2,A3,A4,B1,C1,E1}
    (D1 is structural-only — see MODEL_ATTACK_CLASS_CODES), and uses only known
    predicates."""
    cases = load_cases(ROOT / "attacks")

    # (a) volume
    assert len(cases) >= 10, f"expected >= 10 seed cases, got {len(cases)}"

    # (b) class-code coverage (by id prefix)
    covered = {_class_code(c) for c in cases}
    missing = MODEL_ATTACK_CLASS_CODES - covered
    assert not missing, f"seed corpus missing class codes: {sorted(missing)}"

    # (c) every win_condition predicate is in the closed grammar
    for c in cases:
        assert c.win_condition, f"{c.id}: empty win_condition"
        for pred in c.win_condition:
            assert pred in KNOWN_PREDICATES, f"{c.id}: unknown predicate {pred!r}"


def test_all_held_out_cases_load():
    """The HELD-OUT generalization corpus in red-team/attacks/held_out/ loads +
    validates independently of the seed corpus (load_cases globs non-recursively,
    so held_out/ is a separate directory), has >= 8 cases, covers all seven
    MODEL-attack case-class codes {A1,A2,A3,A4,B1,C1,E1} (D1 is structural-only —
    see MODEL_ATTACK_CLASS_CODES), and uses only known predicates."""
    cases = load_cases(ROOT / "attacks" / "held_out")

    # (a) volume
    assert len(cases) >= 8, f"expected >= 8 held-out cases, got {len(cases)}"

    # (b) class-code coverage (by id prefix)
    covered = {_class_code(c) for c in cases}
    missing = MODEL_ATTACK_CLASS_CODES - covered
    assert not missing, f"held-out corpus missing class codes: {sorted(missing)}"

    # (c) every win_condition predicate is in the closed grammar
    for c in cases:
        assert c.win_condition, f"{c.id}: empty win_condition"
        for pred in c.win_condition:
            assert pred in KNOWN_PREDICATES, f"{c.id}: unknown predicate {pred!r}"
