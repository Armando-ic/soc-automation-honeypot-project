from detection_authoring.report import AuthoringRun, build_authoring_report
from detection_authoring.stats import clopper_pearson


def test_clopper_pearson_edges():
    assert clopper_pearson(0, 5)[0] == 0.0
    assert clopper_pearson(5, 5)[1] == 1.0


def test_clopper_pearson_interior_value():
    # exact Clopper-Pearson for 5/20 (matches statsmodels beta method / R
    # binom.test); guards against a swapped beta.ppf argument the edge test,
    # which only hits the hard-coded 0.0/1.0 branches, would not catch
    lo, hi = clopper_pearson(5, 20)
    assert abs(lo - 0.0866) < 0.001
    assert abs(hi - 0.4910) < 0.001


def test_report_counts_pass_rate_and_tiers():
    runs = [
        AuthoringRun("T1059.001", True, None, "ok"),
        AuthoringRun("T1059.001", False, "t4_tn", "ok"),
        AuthoringRun("T1059.003", False, "t3_tp", "ok"),
        AuthoringRun("T1059.003", False, None, "no_rule"),
    ]
    md = build_authoring_report(runs)
    assert "T1059.001" in md
    assert "1/2" in md          # T1059.001 passed 1 of 2
    assert "t4_tn" in md        # tier breakdown surfaced
    assert "no_rule" in md      # invalid outcome surfaced separately


def test_report_no_valid_runs_shows_full_uncertainty():
    # a technique whose every run is invalid (no rule ever emitted) has zero
    # data, so the CI must be fully uninformative [0.00, 1.00], not a misleading
    # [0.00, 0.00] that reads as "0% pass rate, known for certain"
    runs = [AuthoringRun("T1059.005", False, None, "no_rule")]
    md = build_authoring_report(runs)
    assert "[0.00, 1.00]" in md
    assert "no_rule" in md
