"""Statistical helpers used by the checks. Kept dependency-light and unit-tested."""

from __future__ import annotations

import math
from collections.abc import Callable

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import roc_auc_score


def safe_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    y_true = np.asarray(y_true)
    if len(np.unique(y_true)) < 2:
        return float("nan")
    return float(roc_auc_score(y_true, scores))


def bootstrap_ci(
    fn: Callable[[np.ndarray], float],
    n: int,
    *,
    rounds: int = 300,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile bootstrap interval for a statistic computed on row indices."""
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(rounds):
        idx = rng.integers(0, n, size=n)
        value = fn(idx)
        if not math.isnan(value):
            values.append(value)
    if not values:
        return (float("nan"), float("nan"))
    lo, hi = np.percentile(values, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(lo), float(hi)


def rate(mask: np.ndarray) -> float:
    mask = np.asarray(mask, dtype=bool)
    return float(mask.mean()) if mask.size else float("nan")


def true_positive_rate(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    pos = np.asarray(y_true) == 1
    return rate(np.asarray(y_pred)[pos] == 1) if pos.any() else float("nan")


def false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    neg = np.asarray(y_true) == 0
    return rate(np.asarray(y_pred)[neg] == 1) if neg.any() else float("nan")


def two_proportion_pvalue(k1: int, n1: int, k2: int, n2: int) -> float:
    """Two-sided z-test p-value for a difference between two proportions."""
    if min(n1, n2) == 0:
        return float("nan")
    p_pool = (k1 + k2) / (n1 + n2)
    se = math.sqrt(p_pool * (1 - p_pool) * (1 / n1 + 1 / n2))
    if se == 0:
        return 1.0
    z = (k1 / n1 - k2 / n2) / se
    return float(2 * stats.norm.sf(abs(z)))


def expected_calibration_error(y_true: np.ndarray, probs: np.ndarray, bins: int = 10) -> float:
    """ECE with equal-width bins (Guo et al., 2017)."""
    y_true = np.asarray(y_true, dtype=float)
    probs = np.asarray(probs, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    ids = np.clip(np.digitize(probs, edges[1:-1], right=True), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        in_bin = ids == b
        if in_bin.any():
            ece += in_bin.mean() * abs(probs[in_bin].mean() - y_true[in_bin].mean())
    return float(ece)


def adaptive_calibration_error(y_true: np.ndarray, probs: np.ndarray, bins: int = 10) -> float:
    """ECE with equal-mass bins (Nixon et al., CVPR Workshops 2019).

    Equal-width bins leave most bins nearly empty when scores cluster near 0 or 1, which
    biases ECE; equal-mass bins hold the same number of predictions each.
    """
    y_true = np.asarray(y_true, dtype=float)
    probs = np.asarray(probs, dtype=float)
    if len(probs) == 0:
        return float("nan")
    order = np.argsort(probs, kind="stable")
    total = 0.0
    for idx in np.array_split(order, min(bins, len(probs))):
        if len(idx):
            total += len(idx) / len(probs) * abs(probs[idx].mean() - y_true[idx].mean())
    return float(total)


def reliability_table(y_true: np.ndarray, probs: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.linspace(0.0, 1.0, bins + 1)
    ids = np.clip(np.digitize(probs, edges[1:-1], right=True), 0, bins - 1)
    rows = []
    for b in range(bins):
        in_bin = ids == b
        if in_bin.any():
            rows.append(
                {
                    "bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}",
                    "count": int(in_bin.sum()),
                    "mean_predicted": float(np.mean(probs[in_bin])),
                    "observed_rate": float(np.mean(np.asarray(y_true)[in_bin])),
                }
            )
    return rows


def population_stability_index(reference: pd.Series, current: pd.Series, bins: int = 10) -> float:
    """PSI between two samples. Numeric columns use reference quantile bins."""
    eps = 1e-6
    ref = reference.dropna()
    cur = current.dropna()
    if ref.empty or cur.empty:
        return float("nan")
    if pd.api.types.is_numeric_dtype(ref) and ref.nunique() > bins:
        edges = np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1)))
        edges[0], edges[-1] = -np.inf, np.inf
        ref_counts = np.histogram(ref, bins=edges)[0]
        cur_counts = np.histogram(cur, bins=edges)[0]
    else:
        cats = sorted(set(ref.astype(str)) | set(cur.astype(str)))
        ref_counts = ref.astype(str).value_counts().reindex(cats, fill_value=0).to_numpy()
        cur_counts = cur.astype(str).value_counts().reindex(cats, fill_value=0).to_numpy()
    ref_pct = ref_counts / max(ref_counts.sum(), 1) + eps
    cur_pct = cur_counts / max(cur_counts.sum(), 1) + eps
    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))


def distribution_test(reference: pd.Series, current: pd.Series) -> tuple[str, float]:
    """KS test for numeric columns, chi-square for categorical ones."""
    ref = reference.dropna()
    cur = current.dropna()
    if pd.api.types.is_numeric_dtype(ref) and ref.nunique() > 10:
        return "ks", float(stats.ks_2samp(ref, cur).pvalue)
    cats = sorted(set(ref.astype(str)) | set(cur.astype(str)))
    table = np.vstack(
        [
            ref.astype(str).value_counts().reindex(cats, fill_value=0).to_numpy(),
            cur.astype(str).value_counts().reindex(cats, fill_value=0).to_numpy(),
        ]
    )
    table = table[:, table.sum(axis=0) > 0]
    if table.shape[1] < 2:
        return "chi2", 1.0
    return "chi2", float(stats.chi2_contingency(table)[1])


def single_feature_auc(feature: pd.Series, target: pd.Series) -> float:
    """How well one feature alone separates a binary target (symmetrised to >= 0.5).

    Categorical features are target-encoded first, which makes this a fast,
    model-free association measure for proxy and leakage screening. The encoding is
    out-of-fold: each row's category is encoded from the other folds only. Encoding a row
    with its own label lets a column of unique IDs (pure noise) score AUC 1.0 and be
    reported as leakage.
    """
    df = pd.DataFrame({"x": feature, "y": target}).dropna()
    if df["y"].nunique() < 2 or df["x"].nunique() < 2:
        return 0.5
    if pd.api.types.is_numeric_dtype(df["x"]):
        x = df["x"].astype(float)
    else:
        # Smoothed (m = 20) so rare categories shrink to the prior; 5 shuffled, seeded folds
        # so the result is reproducible and does not depend on row order.
        prior, m = float(df["y"].mean()), 20.0
        fold = np.random.default_rng(0).permutation(len(df)) % 5
        x = pd.Series(prior, index=df.index, dtype=float)
        for k in range(5):
            held = fold == k
            grouped = df[~held].groupby("x")["y"].agg(["sum", "count"])
            encoding = (grouped["sum"] + m * prior) / (grouped["count"] + m)
            x[held] = df.loc[held, "x"].map(encoding).fillna(prior).to_numpy()
    auc = roc_auc_score(df["y"], x)
    return float(max(auc, 1 - auc))


def proxy_strength(feature: pd.Series, protected: pd.Series) -> float:
    """Max one-vs-rest AUC of a feature for predicting any protected group."""
    best = 0.5
    for group in protected.dropna().unique():
        best = max(best, single_feature_auc(feature, (protected == group).astype(int)))
    return best


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (better than normal at small n)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))
