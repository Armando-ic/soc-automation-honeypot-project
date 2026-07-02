"""Statistical honesty for the baseline report (§8, consumed by Task 15).

Turns per-class trial counts (k bypasses out of n trials) into exact binomial
confidence intervals, a two-proportion significance test, and a
multiple-comparison correction across classes.

- `clopper_pearson`: exact binomial CI for a single class's bypass rate.
- `fisher_two_proportion`: exact p-value for whether two classes' bypass
  rates differ (e.g. class vs. baseline, or before/after a mitigation).
- `holm_bonferroni`: step-down adjustment of a batch of p-values (one per
  class) so that running many significance tests doesn't inflate the
  false-positive rate.

Pure math, fully offline, deterministic. Reuses `scipy.stats.beta` (for the
Clopper-Pearson quantiles) and `scipy.stats.fisher_exact` (for the exact
test) rather than re-implementing either.
"""
from __future__ import annotations

from scipy.stats import beta, fisher_exact


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact binomial confidence interval for k successes out of n trials.

    Uses the Beta-distribution quantile relationship: the lower bound is the
    alpha/2 quantile of Beta(k, n-k+1) and the upper bound is the 1-alpha/2
    quantile of Beta(k+1, n-k), with the degenerate edges (k=0 -> lower=0.0,
    k=n -> upper=1.0) handled explicitly since Beta(0, ...) and Beta(..., 0)
    are undefined.
    """
    lower = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    upper = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lower), float(upper)


def fisher_two_proportion(k1: int, n1: int, k2: int, n2: int) -> float:
    """Exact two-sided p-value for whether two bypass rates (k1/n1 vs k2/n2)
    differ, via Fisher's exact test on the 2x2 contingency table
    [[successes, failures], [successes, failures]]."""
    table = [[k1, n1 - k1], [k2, n2 - k2]]
    return float(fisher_exact(table)[1])


def holm_bonferroni(pvalues: list[float]) -> list[float]:
    """Holm step-down multiple-comparison correction.

    1. Sort p-values ascending, remembering original indices.
    2. For the i-th smallest (1-indexed), adjusted_i = p_i * (m - i + 1).
    3. Enforce monotonic non-decreasing adjusted values via a running
       (cumulative) maximum across the sorted sequence.
    4. Clip each adjusted value to [0.0, 1.0].
    5. Return the adjusted p-values in the ORIGINAL input order (mapped back
       via the remembered indices) — NOT in sorted order.
    """
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])

    adjusted_sorted: list[float] = []
    running_max = 0.0
    for rank, idx in enumerate(order, start=1):
        candidate = pvalues[idx] * (m - rank + 1)
        running_max = max(running_max, candidate)
        clipped = min(1.0, max(0.0, running_max))
        adjusted_sorted.append(clipped)

    result = [0.0] * m
    for sorted_pos, idx in enumerate(order):
        result[idx] = adjusted_sorted[sorted_pos]
    return result
