"""Data integrity: missingness, duplicates, class balance and target leakage."""

from __future__ import annotations

import re

import pandas as pd

from pramana.context import AuditContext
from pramana.metrics import single_feature_auc
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status


@register(
    "data_quality.integrity",
    title="Data quality",
    category="Data",
    system_types=("tabular_classifier",),
    order=5,
)
def integrity(ctx: AuditContext) -> CheckResult:
    miss_max = ctx.spec.threshold("missing_rate_max")
    dup_max = ctx.spec.threshold("duplicate_rate_max")
    leak_max = ctx.spec.threshold("leakage_auc_max")

    datasets = {"evaluation_data": ctx.eval_df}
    if ctx.ref_df is not None:
        datasets["reference_data"] = ctx.ref_df

    issues, notes = [], []
    per_dataset = {}
    for name, df in datasets.items():
        cols = [c for c in ctx.feature_columns + [ctx.spec.target] if c in df.columns]
        missing = df[cols].isna().mean()
        high_missing = {c: round(float(v), 4) for c, v in missing.items() if v > miss_max}
        # A duplicate is a row repeated in full, record identifier included. Without an
        # identifier, two identical rows may be two people who share every recorded value
        # (common when there are few, coarse columns), so they are noted, not graded.
        id_cols = [
            c
            for c in df.columns
            if re.search(r"(^|_)id$", str(c), re.IGNORECASE)
            or (c in ctx.spec.exclude_columns and df[c].nunique() >= 0.9 * len(df))
        ]
        dup_rate = float(df.duplicated().mean())
        # Balance from labelled rows: this check reports missing labels (above), it must
        # not fail on them the way the metric checks do.
        labelled = df[df[ctx.spec.target].notna()] if ctx.spec.target in df.columns else None
        target_balance = (
            float(ctx.y(labelled).mean()) if labelled is not None and len(labelled) else None
        )
        per_dataset[name] = {
            "rows": int(len(df)),
            "high_missing": high_missing,
            "duplicate_rate": round(dup_rate, 4),
            "positive_rate": round(target_balance, 4) if target_balance is not None else None,
        }
        if high_missing:
            issues.append(
                f"{name}: missing values above {miss_max:.0%} in {', '.join(high_missing)}"
            )
        per_dataset[name]["record_identifier"] = id_cols or None
        if dup_rate > dup_max and id_cols:
            issues.append(f"{name}: {dup_rate:.1%} duplicate rows")
        elif dup_rate > dup_max:
            notes.append(
                f"{name}: {dup_rate:.1%} of rows are identical to another, but the data has no "
                "record identifier, so they may be different people with the same values"
            )
        if target_balance is not None and min(target_balance, 1 - target_balance) < 0.05:
            issues.append(f"{name}: severe class imbalance ({target_balance:.1%} positive)")

    leakage = []
    source = ctx.ref_df if ctx.ref_df is not None else ctx.eval_df
    if ctx.spec.target in source.columns:
        source = source[source[ctx.spec.target].notna()]
        y = pd.Series(ctx.y(source), index=source.index)
        for feature in ctx.feature_columns:
            if feature in source.columns:
                auc = single_feature_auc(source[feature], y)
                if auc > leak_max:
                    leakage.append({"feature": feature, "auc": round(auc, 4)})

    if leakage:
        status, severity = Status.FAIL, Severity.HIGH
        issues.append(
            "possible target leakage: "
            + ", ".join(f"{x['feature']} (AUC {x['auc']:.2f})" for x in leakage)
        )
    elif issues:
        status, severity = Status.WARN, Severity.LOW
    else:
        status, severity = Status.PASS, Severity.INFO

    return CheckResult(
        check_id="data_quality.integrity",
        title="Data quality",
        category="Data",
        status=status,
        severity=severity,
        summary=(
            (
                "Issues: " + "; ".join(issues) + "."
                if issues
                else "No data-quality issues above thresholds."
            )
            + (" Note: " + "; ".join(notes) + "." if notes else "")
        ),
        plain_summary=(
            "Some input data is incomplete or duplicated, which can skew test results."
            if issues and not leakage
            else "An input appears to contain the answer the model is predicting, so test results may be inflated."
            if leakage
            else "The data supplied for the audit is complete and consistent."
        ),
        recommendation=(
            "Document how missing values are handled, de-duplicate records, and confirm no input is "
            "recorded after the outcome it predicts."
        ),
        metrics={"issues": len(issues), "leakage_suspects": len(leakage)},
        details={"datasets": per_dataset, "leakage": leakage},
    )
