import numpy as np
import pandas as pd
import pytest

from pramana.checks.fairness import group_table, parity_summary


def _toy(rate_a: float, rate_b: float, n: int = 2000):
    half = n // 2
    groups = pd.Series(np.repeat(["a", "b"], half))
    pred = np.r_[np.arange(half) < rate_a * half, np.arange(half) < rate_b * half].astype(int)
    y = pred.copy()
    scores = pred.astype(float)
    return groups, y, pred, scores


def test_disparate_impact_ratio_matches_construction():
    groups, y, pred, scores = _toy(0.8, 0.4)
    summary = parity_summary(group_table(groups, y, pred, scores, min_n=30))
    assert summary["disparate_impact_ratio"] == pytest.approx(0.5)
    assert summary["least_favoured"] == "b"
    assert summary["p_value"] < 1e-6


def test_equal_rates_pass_four_fifths():
    groups, y, pred, scores = _toy(0.6, 0.6)
    summary = parity_summary(group_table(groups, y, pred, scores, min_n=30))
    assert summary["disparate_impact_ratio"] > 0.9


def test_small_groups_are_excluded_from_comparison():
    groups = pd.Series(["a"] * 500 + ["tiny"] * 10)
    pred = np.r_[np.ones(500), np.zeros(10)].astype(int)
    rows = group_table(groups, pred, pred, pred.astype(float), min_n=30)
    summary = parity_summary(rows)
    assert summary["comparable_groups"] == 1
    assert "disparate_impact_ratio" not in summary
