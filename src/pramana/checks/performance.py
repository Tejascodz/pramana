"""Predictive performance with uncertainty, compared against the declared minimum."""

from __future__ import annotations

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from pramana.context import AuditContext
from pramana.metrics import bootstrap_ci, safe_auc
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status


@register(
    "performance.discrimination",
    title="Predictive performance",
    category="Performance",
    system_types=("tabular_classifier",),
    order=10,
)
def discrimination(ctx: AuditContext) -> CheckResult:
    y, scores, pred = ctx.eval_y, ctx.eval_scores, ctx.eval_pred
    min_auc = ctx.spec.threshold("min_auc")

    auc = safe_auc(y, scores)
    lo, hi = bootstrap_ci(lambda idx: safe_auc(y[idx], scores[idx]), len(y), seed=ctx.spec.seed)
    metrics = {
        "auc": round(auc, 4),
        "auc_ci_low": round(lo, 4),
        "auc_ci_high": round(hi, 4),
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "positive_rate_observed": round(float(y.mean()), 4),
        "positive_rate_predicted": round(float(pred.mean()), 4),
        "n_eval": int(len(y)),
        "min_auc": min_auc,
    }

    gap_note = ""
    if ctx.ref_df is not None and ctx.spec.target in ctx.ref_df.columns:
        train_auc = safe_auc(ctx.y(ctx.ref_df), ctx.score(ctx.ref_df))
        metrics["train_auc"] = round(train_auc, 4)
        metrics["generalization_gap"] = round(train_auc - auc, 4)
        if train_auc - auc > 0.05:
            gap_note = (
                f" Training AUC is {train_auc:.3f}, {train_auc - auc:.3f} higher than on held-out data,"
                " which suggests overfitting."
            )

    if auc < min_auc:
        status, severity = Status.FAIL, Severity.HIGH
        verdict = "below"
    elif lo < min_auc:
        status, severity = Status.WARN, Severity.MEDIUM
        verdict = "above, but its 95% confidence interval reaches below,"
    else:
        status, severity = Status.PASS, Severity.INFO
        verdict = "above"
    if gap_note and status == Status.PASS:
        status, severity = Status.WARN, Severity.LOW

    return CheckResult(
        check_id="performance.discrimination",
        title="Predictive performance",
        category="Performance",
        status=status,
        severity=severity,
        summary=(
            f"AUC {auc:.3f} (95% CI {lo:.3f}-{hi:.3f}) on {len(y)} held-out rows is {verdict} the "
            f"declared minimum of {min_auc:.2f}. Accuracy {metrics['accuracy']:.3f}, "
            f"F1 {metrics['f1']:.3f} at threshold {ctx.spec.decision_threshold}." + gap_note
        ),
        plain_summary=(
            f"The model tells good and bad outcomes apart correctly about {auc:.0%} of the time, "
            f"{'which meets' if status != Status.FAIL else 'which does not meet'} the bar set for this use."
        ),
        recommendation=(
            "Retrain or recalibrate before release and re-validate on data that reflects deployment."
            if status == Status.FAIL
            else "Track AUC in production monitoring with an alert at the declared minimum."
        ),
        metrics=metrics,
    )
