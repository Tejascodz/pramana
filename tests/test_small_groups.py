"""Groups too small for the fairness ratios are compared exactly (Fisher, Holm-corrected).

A small group that is clearly less favoured is flagged for review; a small group within
chance of the others is not; and with many small groups of identical rates, the Holm
correction keeps chance findings from being reported.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from pramana.checks.fairness import compare_small_groups, group_table


def _rows(sizes_rates: dict[str, tuple[int, float]], seed: int = 0, min_n: int = 30):
    rng = np.random.default_rng(seed)
    groups, preds = [], []
    for name, (n, rate) in sizes_rates.items():
        favourable = int(round(n * rate))
        p = np.r_[np.ones(favourable), np.zeros(n - favourable)]
        rng.shuffle(p)
        groups += [name] * n
        preds += list(p)
    pred = np.array(preds, dtype=int)
    y = pred.copy()
    return group_table(pd.Series(groups), y, pred, pred.astype(float), min_n)


def test_a_small_group_that_is_clearly_less_favoured_is_flagged():
    rows = _rows({"A": (500, 0.7), "B": (500, 0.7), "C": (20, 0.0)})
    flagged = compare_small_groups(rows, 0.8)
    assert [r["group"] for r in flagged] == ["C"]
    test = flagged[0]["small_group_test"]
    assert test["p_value"] < 0.001 and test["significant_after_correction"]
    assert test["rate_ci"][0] == 0.0 and test["rate_ci"][1] < 0.2  # Wilson interval


def test_a_small_group_within_chance_is_not():
    rows = _rows({"A": (500, 0.7), "B": (500, 0.7), "C": (20, 0.6)})
    assert compare_small_groups(rows, 0.8) == []
    assert "p_value" in next(r for r in rows if r["group"] == "C")["small_group_test"]


def test_a_small_group_favoured_more_is_not_flagged():
    rows = _rows({"A": (500, 0.5), "B": (500, 0.5), "C": (20, 1.0)})
    assert compare_small_groups(rows, 0.8) == []


def test_many_small_groups_with_the_same_rate_raise_no_alarm():
    """Twenty small groups drawn at the same rate as everyone else: Holm keeps chance
    findings out, across many seeds."""
    alarms = 0
    for seed in range(30):
        rng = np.random.default_rng(seed)
        spec = {"big": (2000, 0.6)} | {f"g{i}": (int(rng.integers(8, 29)), 0.6) for i in range(20)}
        rows = _rows(spec, seed)
        for r in rows:  # draw small-group outcomes at random around the same rate
            if r["group"] != "big":
                r["favourable"] = int(rng.binomial(r["n"], 0.6))
                r["selection_rate"] = r["favourable"] / r["n"]
        alarms += bool(compare_small_groups(rows, 0.8))
    assert alarms <= 2  # about 5% expected at most; observed far fewer


def test_rows_with_no_recorded_attribute_are_never_tested():
    from pramana.context import MISSING_GROUP

    rows = _rows({"A": (500, 0.7), MISSING_GROUP: (20, 0.0)})
    assert compare_small_groups(rows, 0.8) == []
