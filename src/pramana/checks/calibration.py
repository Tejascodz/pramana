"""Probability calibration overall and within protected groups."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import brier_score_loss

from pramana.context import AuditContext
from pramana.metrics import expected_calibration_error, reliability_table
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status


@register(
    "calibration.reliability",
    title="Calibration",
    category="Performance",
    system_types=("tabular_classifier",),
    order=15,
)
def reliability(ctx: AuditContext) -> CheckResult:
    y, p = ctx.eval_y, ctx.eval_scores
    limit = ctx.spec.threshold("ece_max")
    min_n = int(ctx.spec.threshold("min_group_size"))
    ece = expected_calibration_error(y, p)
    brier = float(brier_score_loss(y, np.clip(p, 0, 1)))

    group_ece: dict[str, dict[str, float]] = {}
    for attr in ctx.spec.sensitive_features:
        if attr not in ctx.eval_df.columns:
            continue
        values = ctx.eval_df[attr].astype(str).to_numpy()
        group_ece[attr] = {
            g: round(expected_calibration_error(y[values == g], p[values == g]), 4)
            for g in sorted(set(values))
            if (values == g).sum() >= min_n
        }
    worst_group = max(
        ((a, g, v) for a, d in group_ece.items() for g, v in d.items()),
        key=lambda t: t[2],
        default=None,
    )

    if ece > 2 * limit:
        status, severity = Status.FAIL, Severity.MEDIUM
    elif ece > limit or (worst_group and worst_group[2] > 2 * limit):
        status, severity = Status.WARN, Severity.LOW
    else:
        status, severity = Status.PASS, Severity.INFO

    summary = f"Expected calibration error {ece:.3f} (limit {limit}), Brier score {brier:.3f}."
    if worst_group:
        summary += f" Worst group: {worst_group[0]}={worst_group[1]} with ECE {worst_group[2]:.3f}."
    return CheckResult(
        check_id="calibration.reliability",
        title="Calibration",
        category="Performance",
        status=status,
        severity=severity,
        summary=summary,
        plain_summary=(
            "Risk scores can be read as real probabilities."
            if status == Status.PASS
            else "Risk scores do not match observed outcome rates closely enough to be read as probabilities."
        ),
        recommendation="Apply isotonic or Platt calibration on a held-out set and re-check per group.",
        metrics={"ece": round(ece, 4), "brier": round(brier, 4)},
        details={"reliability": reliability_table(y, p), "group_ece": group_ece},
    )
