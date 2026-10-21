"""Global decision drivers, checked against what the documentation says they are."""

from __future__ import annotations

from sklearn.inspection import permutation_importance

from pramana.context import AuditContext, MissingArtifact
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status

MAX_ROWS = 2000


@register(
    "explainability.feature_importance",
    title="Decision drivers",
    category="Transparency",
    system_types=("tabular_classifier",),
    order=50,
)
def feature_importance(ctx: AuditContext) -> CheckResult:
    if not ctx.has_model:
        raise MissingArtifact("Feature importance needs the model")
    df = ctx.eval_df
    if len(df) > MAX_ROWS:
        df = df.sample(MAX_ROWS, random_state=ctx.spec.seed)
    X, y = ctx.X(df), ctx.y(df)

    result = permutation_importance(
        ctx.model, X, y, scoring="roc_auc", n_repeats=5, random_state=ctx.spec.seed
    )
    ranking = sorted(
        (
            {"feature": f, "importance": round(float(m), 5), "std": round(float(s), 5)}
            for f, m, s in zip(
                X.columns, result.importances_mean, result.importances_std, strict=True
            )
        ),
        key=lambda r: -r["importance"],
    )
    positive_total = sum(max(r["importance"], 0) for r in ranking) or 1.0
    for r in ranking:
        r["share"] = round(max(r["importance"], 0) / positive_total, 4)

    declared = set((ctx.documentation or {}).get("key_drivers", []) or [])
    top5 = [r["feature"] for r in ranking[:5] if r["importance"] > 0]
    undocumented = [f for f in top5 if declared and f not in declared]
    sensitive_inputs = [f for f in X.columns if f in ctx.spec.sensitive_features]

    if sensitive_inputs:
        status, severity = Status.FAIL, Severity.HIGH
    elif not declared:
        status, severity = Status.WARN, Severity.LOW
    elif undocumented:
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    summary = (
        "Top drivers by permutation importance (AUC drop): "
        + ", ".join(f"{r['feature']} ({r['share']:.0%})" for r in ranking[:5])
        + "."
    )
    if not declared:
        summary += " The documentation does not declare expected key drivers, so they cannot be reconciled."
    elif undocumented:
        summary += f" Not declared in documentation: {', '.join(undocumented)}."
    if sensitive_inputs:
        summary += f" Protected attributes used as inputs: {', '.join(sensitive_inputs)}."

    return CheckResult(
        check_id="explainability.feature_importance",
        title="Decision drivers",
        category="Transparency",
        status=status,
        severity=severity,
        summary=summary,
        plain_summary=(
            f"The decision is driven mostly by {', '.join(top5[:3])}"
            + (
                "; some of these drivers are not described in the documentation."
                if undocumented
                else "."
            )
        ),
        recommendation=(
            "Declare expected key drivers in the model documentation, explain any surprising driver, "
            "and provide reason codes for individual adverse decisions."
        ),
        metrics={"top_feature": ranking[0]["feature"], "top_feature_share": ranking[0]["share"]},
        details={
            "ranking": ranking,
            "declared_drivers": sorted(declared),
            "undocumented": undocumented,
        },
    )
