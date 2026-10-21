"""Data integrity: missingness, duplicates, class balance and target leakage."""

from __future__ import annotations

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

    issues = []
    per_dataset = {}
    for name, df in datasets.items():
        cols = [c for c in ctx.feature_columns + [ctx.spec.target] if c in df.columns]
        missing = df[cols].isna().mean()
        high_missing = {c: round(float(v), 4) for c, v in missing.items() if v > miss_max}
        dup_rate = float(df[cols].duplicated().mean())
        target_balance = float(ctx.y(df).mean()) if ctx.spec.target in df.columns else None
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
        if dup_rate > dup_max:
            issues.append(f"{name}: {dup_rate:.1%} duplicate rows")
        if target_balance is not None and min(target_balance, 1 - target_balance) < 0.05:
            issues.append(f"{name}: severe class imbalance ({target_balance:.1%} positive)")

    leakage = []
    source = ctx.ref_df if ctx.ref_df is not None else ctx.eval_df
    if ctx.spec.target in source.columns:
        y = ctx.y(source)
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
        summary=("Issues: " + "; ".join(issues) + ".")
        if issues
        else "No data-quality issues above thresholds.",
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
