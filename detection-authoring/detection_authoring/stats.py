"""Exact binomial CI for the authoring pass-rate. Copied (not imported) so this
package never depends on the frozen red-team harness."""
from __future__ import annotations

from scipy.stats import beta


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    lower = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    upper = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lower), float(upper)
