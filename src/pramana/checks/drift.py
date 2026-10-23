"""Data and prediction drift between validation data and the latest production sample."""

from __future__ import annotations

import numpy as np
import pandas as pd

from pramana.context import AuditContext, MissingArtifact
from pramana.metrics import distribution_test, population_stability_index
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status


def feature_drift(reference: pd.DataFrame, current: pd.DataFrame, columns: list[str]) -> list[dict]:
    rows = []
    for col in columns:
        if col not in reference.columns or col not in current.columns:
            continue
        test, p_value = distribution_test(reference[col], current[col])
        rows.append(
            {
                "feature": col,
                "psi": round(population_stability_index(reference[col], current[col]), 4),
                "test": test,
                "p_value": p_value,
            }
        )
    # PSI is NaN when a feature cannot be binned (for example a constant column). Keep those
    # rows as evidence but sort them last, so they never displace a measured shift.
    rows.sort(key=lambda r: (bool(np.isnan(r["psi"])), -r["psi"] if not np.isnan(r["psi"]) else 0))
    return rows


@register(
    "drift.population_stability",
    title="Data and prediction drift",
    category="Monitoring",
    system_types=("tabular_classifier",),
    order=40,
)
def population_stability(ctx: AuditContext) -> CheckResult:
    if ctx.ref_df is None:
        raise MissingArtifact("Drift analysis needs artifacts.reference_data")
    current_name = "production_data" if ctx.prod_df is not None else "evaluation_data"
    current = ctx.prod_df if ctx.prod_df is not None else ctx.eval_df
    warn, fail = ctx.spec.threshold("psi_warn"), ctx.spec.threshold("psi_fail")

    rows = feature_drift(ctx.ref_df, current, ctx.feature_columns)
    ref_scores = ctx.score(ctx.ref_df)
    cur_scores = ctx.score(current)
    score_psi = population_stability_index(pd.Series(ref_scores), pd.Series(cur_scores))
    ref_rate = float(ctx.decide(ref_scores).mean())
    cur_rate = float(ctx.decide(cur_scores).mean())

    measured = [r for r in rows if not np.isnan(r["psi"])]
    unmeasured = [r["feature"] for r in rows if np.isnan(r["psi"])]
    major = [r for r in measured if r["psi"] >= fail]
    moderate = [r for r in measured if warn <= r["psi"] < fail]
    if score_psi >= fail or (major and score_psi >= warn):
        status, severity = Status.FAIL, Severity.HIGH
    elif major or moderate or score_psi >= warn:
        # Inputs moved but scores are stable: representativeness risk, not yet an output shift.
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    top = ", ".join(f"{r['feature']} (PSI {r['psi']:.2f})" for r in measured[:3]) or "none"
    shifted = (major + moderate)[0]["feature"] if (major or moderate) else None
    return CheckResult(
        check_id="drift.population_stability",
        title="Data and prediction drift",
        category="Monitoring",
        status=status,
        severity=severity,
        summary=(
            f"Compared reference data with {current_name} ({len(current)} rows). "
            f"{len(major)} features with major drift (PSI >= {fail}), {len(moderate)} moderate. "
            f"Largest shifts: {top}. Score PSI {score_psi:.3f}; favourable-decision rate moved from "
            f"{ref_rate:.1%} to {cur_rate:.1%}."
            + (f" PSI could not be computed for {', '.join(unmeasured)}." if unmeasured else "")
        ),
        plain_summary=(
            "Today's applicants look materially different from the people the model learned from, and "
            "its scores have shifted with them, so validated accuracy and fairness may no longer hold."
            if status == Status.FAIL
            else "Incoming data still resembles the data the model was validated on."
            if status == Status.PASS
            else "Today's applicants differ from the people the model learned from (for example "
            f"{shifted}), although overall scores have not moved much yet."
            if shifted
            else "The model's scores have started to move away from validation, although no single "
            "input has drifted much yet."
        ),
        recommendation=(
            "Re-validate performance and fairness on recent labelled data, review the drivers of the "
            "largest shifts, and set PSI alerts in production monitoring."
        ),
        metrics={
            "score_psi": round(float(score_psi), 4),
            "max_feature_psi": measured[0]["psi"] if measured else 0.0,
            "features_unmeasured": len(unmeasured),
            "features_major_drift": len(major),
            "features_moderate_drift": len(moderate),
            "favourable_rate_reference": round(ref_rate, 4),
            "favourable_rate_current": round(cur_rate, 4),
        },
        details={
            "features": rows,
            "compared_with": current_name,
            "score_shift": round(float(np.mean(cur_scores) - np.mean(ref_scores)), 4),
        },
    )
