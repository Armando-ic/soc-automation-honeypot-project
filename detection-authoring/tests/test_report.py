from detection_authoring.report import AuthoringRun, build_authoring_report
from detection_authoring.stats import clopper_pearson


def test_clopper_pearson_edges():
    assert clopper_pearson(0, 5)[0] == 0.0
    assert clopper_pearson(5, 5)[1] == 1.0


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
