import numpy as np
import pandas as pd
import pytest

from pramana.metrics import (
    bootstrap_ci,
    expected_calibration_error,
    population_stability_index,
    proxy_strength,
    safe_auc,
    single_feature_auc,
    two_proportion_pvalue,
)


def test_ece_is_near_zero_for_calibrated_scores():
    rng = np.random.default_rng(0)
    p = rng.uniform(0, 1, 20_000)
    y = (rng.uniform(0, 1, 20_000) < p).astype(int)
    assert expected_calibration_error(y, p) < 0.02


def test_ece_detects_overconfidence():
    rng = np.random.default_rng(0)
    p = rng.uniform(0, 1, 20_000)
    y = (rng.uniform(0, 1, 20_000) < p).astype(int)
    overconfident = np.clip(p * 1.6 - 0.3, 0, 1)
    assert expected_calibration_error(y, overconfident) > 0.08


def test_psi_identical_and_shifted():
    rng = np.random.default_rng(1)
    ref = pd.Series(rng.normal(0, 1, 5000))
    assert population_stability_index(ref, ref.copy()) < 0.01
    assert population_stability_index(ref, ref + 1.0) > 0.25


def test_psi_categorical():
    ref = pd.Series(["a"] * 500 + ["b"] * 500)
    cur = pd.Series(["a"] * 900 + ["b"] * 100)
    assert population_stability_index(ref, cur) > 0.25


def test_two_proportion_pvalue():
    assert two_proportion_pvalue(50, 100, 50, 100) == pytest.approx(1.0)
    assert two_proportion_pvalue(90, 100, 50, 100) < 1e-6


def test_safe_auc_single_class_is_nan():
    assert np.isnan(safe_auc(np.ones(10), np.linspace(0, 1, 10)))


def test_bootstrap_ci_contains_point_estimate():
    rng = np.random.default_rng(3)
    y = rng.integers(0, 2, 2000)
    s = y * 0.6 + rng.normal(0, 0.5, 2000)
    auc = safe_auc(y, s)
    lo, hi = bootstrap_ci(lambda idx: safe_auc(y[idx], s[idx]), len(y), rounds=200, seed=1)
    assert lo < auc < hi


def test_single_feature_auc_is_symmetric_and_handles_categories():
    y = pd.Series([0, 0, 1, 1] * 50)
    assert single_feature_auc(pd.Series([1, 2, 3, 4] * 50), y) == pytest.approx(
        single_feature_auc(pd.Series([4, 3, 2, 1] * 50), y)
    )
    assert single_feature_auc(pd.Series(["x", "x", "y", "y"] * 50), y) > 0.95


def test_proxy_strength_flags_a_strong_proxy():
    rng = np.random.default_rng(5)
    group = pd.Series(rng.choice(["rural", "urban"], 2000))
    proxy = group.map({"rural": "E", "urban": "A"})
    noise = pd.Series(rng.normal(size=2000))
    assert proxy_strength(proxy, group) > 0.95
    assert proxy_strength(noise, group) < 0.6
