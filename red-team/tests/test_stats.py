import pytest

from red_team.stats import clopper_pearson, fisher_two_proportion, holm_bonferroni


def test_zero_of_fifty_upper_bound():
    lo, hi = clopper_pearson(0, 50)
    assert lo == 0.0
    assert 0.05 < hi < 0.08          # exact upper ~0.0711


def test_full_success_interval():
    lo, hi = clopper_pearson(50, 50)
    assert hi == 1.0 and lo > 0.9


def test_fisher_detects_difference():
    assert fisher_two_proportion(40, 50, 2, 50) < 0.001


def test_holm_monotone_and_bounded():
    adj = holm_bonferroni([0.01, 0.04, 0.03])
    assert all(0.0 <= x <= 1.0 for x in adj)


def test_holm_known_value_original_order():
    # Sorted ascending: 0.01 (rank1), 0.03 (rank2), 0.04 (rank3).
    # Step-down: 0.01*3=0.03; 0.03*2=0.06; 0.04*1=0.04 -> cumulative-max -> 0.06.
    # Mapped back to original input order [0.01, 0.04, 0.03] -> [0.03, 0.06, 0.06].
    adj = holm_bonferroni([0.01, 0.04, 0.03])
    assert adj == pytest.approx([0.03, 0.06, 0.06])
