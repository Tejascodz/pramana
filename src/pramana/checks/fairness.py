"""Group fairness, intersectional fairness and proxy-feature screening.

A positive prediction is treated as the favourable outcome (for example
"predicted to repay", which leads to approval).
"""

from __future__ import annotations

from itertools import combinations
from typing import Any

import numpy as np
import pandas as pd

from pramana.context import AuditContext, MissingArtifact
from pramana.metrics import (
    false_positive_rate,
    proxy_strength,
    safe_auc,
    true_positive_rate,
    two_proportion_pvalue,
)
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status


def group_table(
    groups: pd.Series, y: np.ndarray, pred: np.ndarray, scores: np.ndarray, min_n: int
) -> list[dict[str, Any]]:
    rows = []
    groups = groups.astype(str).to_numpy()
    for g in sorted(set(groups)):
        mask = groups == g
        n = int(mask.sum())
        rows.append(
            {
                "group": g,
                "n": n,
                "adequate_sample": n >= min_n,
                "selection_rate": float(pred[mask].mean()),
                "favourable": int(pred[mask].sum()),
                "tpr": true_positive_rate(y[mask], pred[mask]),
                "fpr": false_positive_rate(y[mask], pred[mask]),
                "auc": safe_auc(y[mask], scores[mask]),
                "mean_score": float(scores[mask].mean()),
                # Observed positive rate. Where it differs between groups, calibration and
                # equal error rates cannot both hold (Kleinberg et al., 2017).
                "base_rate": float(y[mask].mean()) if n else float("nan"),
            }
        )
    return rows


def parity_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [r for r in rows if r["adequate_sample"]]
    if len(usable) < 2:
        return {"comparable_groups": len(usable)}
    best = max(usable, key=lambda r: r["selection_rate"])
    worst = min(usable, key=lambda r: r["selection_rate"])
    tprs = [r["tpr"] for r in usable if not np.isnan(r["tpr"])]
    fprs = [r["fpr"] for r in usable if not np.isnan(r["fpr"])]
    di = (
        worst["selection_rate"] / best["selection_rate"]
        if best["selection_rate"] > 0
        else float("nan")
    )
    return {
        "comparable_groups": len(usable),
        "most_favoured": best["group"],
        "least_favoured": worst["group"],
        "disparate_impact_ratio": round(di, 4),
        "demographic_parity_difference": round(best["selection_rate"] - worst["selection_rate"], 4),
        "equal_opportunity_difference": round(max(tprs) - min(tprs), 4) if tprs else None,
        "equalized_odds_difference": round(
            max(max(tprs) - min(tprs) if tprs else 0, max(fprs) - min(fprs) if fprs else 0), 4
        ),
        "p_value": two_proportion_pvalue(
            best["favourable"], best["n"], worst["favourable"], worst["n"]
        ),
        "base_rate_difference": _spread([r.get("base_rate") for r in usable]),
    }


def _spread(values: list[Any]) -> float | None:
    known = [float(v) for v in values if v is not None and not np.isnan(v)]
    return round(max(known) - min(known), 4) if len(known) >= 2 else None


def assessable(summary: dict[str, Any]) -> bool:
    """True if at least two adequate groups were compared and the ratio is defined."""
    di = summary.get("disparate_impact_ratio")
    return di is not None and not np.isnan(di)


def _grade(summary: dict[str, Any], di_min: float, eo_max: float) -> tuple[Status, Severity]:
    # Fewer than two comparable groups (or no favourable outcomes at all) means fairness
    # was not tested. That is never a pass: the audit cannot vouch for what it did not measure.
    if not assessable(summary):
        return Status.WARN, Severity.LOW
    di = summary["disparate_impact_ratio"]
    significant = summary["p_value"] < 0.05
    if di < di_min and significant:
        return Status.FAIL, Severity.CRITICAL if di < 0.6 else Severity.HIGH
    if di < di_min or (summary.get("equalized_odds_difference") or 0) > eo_max:
        return Status.WARN, Severity.MEDIUM
    return Status.PASS, Severity.INFO


def _worst(results: list[tuple[Status, Severity]]) -> tuple[Status, Severity]:
    order = {Status.PASS: 0, Status.WARN: 1, Status.FAIL: 2}
    return max(
        results, key=lambda r: (order[r[0]], r[1].rank), default=(Status.PASS, Severity.INFO)
    )


def _present_attributes(ctx: AuditContext) -> list[str]:
    attrs = [a for a in ctx.spec.sensitive_features if a in ctx.eval_df.columns]
    if not attrs:
        raise MissingArtifact("No sensitive_features found in the evaluation data")
    return attrs


@register(
    "fairness.group_parity",
    title="Group fairness",
    category="Fairness",
    system_types=("tabular_classifier",),
    order=20,
)
def group_parity(ctx: AuditContext) -> CheckResult:
    di_min = ctx.spec.threshold("disparate_impact_min")
    eo_max = ctx.spec.threshold("equalized_odds_max")
    min_n = int(ctx.spec.threshold("min_group_size"))
    attrs = _present_attributes(ctx)

    per_attr: dict[str, Any] = {}
    grades = []
    lines = []
    for attr in attrs:
        rows = group_table(ctx.eval_df[attr], ctx.eval_y, ctx.eval_pred, ctx.eval_scores, min_n)
        summary = parity_summary(rows)
        status, severity = _grade(summary, di_min, eo_max)
        grades.append((status, severity))
        per_attr[attr] = {"groups": rows, "summary": summary, "status": status.value}
        if not assessable(summary):
            lines.append(
                f"{attr}: not assessed, only {summary['comparable_groups']} group(s) with at least "
                f"{min_n} records and a defined favourable rate"
            )
        else:
            spread = summary.get("base_rate_difference")
            tension = (
                spread is not None
                and spread >= 0.05
                and (summary.get("equalized_odds_difference") or 0) > eo_max
            )
            lines.append(
                f"{attr}: DI {summary['disparate_impact_ratio']:.2f} "
                f"({summary['least_favoured']} vs {summary['most_favoured']}, p={summary['p_value']:.3g}), "
                f"EOdds diff {summary['equalized_odds_difference']:.2f}"
                + (
                    f" (observed outcome rates differ by {spread:.2f} between groups, so equal "
                    "error rates and calibration cannot both be met; choosing which governs is a "
                    "policy decision)"
                    if tension
                    else ""
                )
            )
    status, severity = _worst(grades)
    failing = [a for a in attrs if per_attr[a]["status"] != Status.PASS.value]

    unassessed = [a for a in attrs if not assessable(per_attr[a]["summary"])]
    # Measured and short of a threshold (four-fifths or equalized odds), as opposed to untested.
    needs_action = [a for a in failing if a not in unassessed]
    worst_attr = min(
        (a for a in attrs if assessable(per_attr[a]["summary"])),
        key=lambda a: per_attr[a]["summary"]["disparate_impact_ratio"],
        default=None,
    )
    metrics = {f"di_{a}": per_attr[a]["summary"].get("disparate_impact_ratio") for a in attrs} | {
        f"eodds_{a}": per_attr[a]["summary"].get("equalized_odds_difference") for a in attrs
    }

    worst_summary = per_attr[worst_attr]["summary"] if worst_attr else None
    untested_note = (
        f" {', '.join(unassessed)} could not be assessed (too few records per group)."
        if unassessed
        else ""
    )
    if worst_summary and worst_summary["disparate_impact_ratio"] < di_min:
        s = worst_summary
        rows = {r["group"]: r for r in per_attr[worst_attr]["groups"]}
        plain = (
            f"Applicants in the '{s['least_favoured']}' group ({worst_attr}) receive a favourable outcome "
            f"{rows[s['least_favoured']]['selection_rate']:.0%} of the time versus "
            f"{rows[s['most_favoured']]['selection_rate']:.0%} for '{s['most_favoured']}', "
            f"below the four-fifths benchmark." + untested_note
        )
    elif needs_action:
        # Every measured DI meets four-fifths, so these attributes fall short on error rates.
        plain = (
            "Outcome rates meet the four-fifths benchmark, but error rates for "
            f"{', '.join(needs_action)} differ across groups more than the equalized-odds limit "
            "allows." + untested_note
        )
    elif unassessed and len(unassessed) == len(attrs):
        plain = (
            "Fairness could not be assessed: no protected attribute had two or more groups large "
            "enough to compare."
        )
    elif unassessed:
        plain = (
            "Outcome rates are within the four-fifths benchmark for the attributes that could be "
            f"tested; {', '.join(unassessed)} could not be assessed (too few records per group)."
        )
    else:
        plain = "Outcome rates are within the four-fifths benchmark across every protected attribute tested."

    return CheckResult(
        check_id="fairness.group_parity",
        title="Group fairness",
        category="Fairness",
        status=status,
        severity=severity,
        summary="; ".join(lines)
        + f". Thresholds: DI >= {di_min}, equalized-odds difference <= {eo_max}.",
        plain_summary=plain,
        recommendation=(
            "Investigate the drivers of the gap (see proxy-feature results), consider reweighing or "
            "threshold adjustment, and document a fairness rationale approved by the risk owner. "
            f"Attributes needing action: {', '.join(needs_action)}."
            + (
                f" Collect at least {min_n} records per group to test {', '.join(unassessed)}."
                if unassessed
                else ""
            )
            if needs_action
            else f"Collect at least {min_n} records for each group of {', '.join(unassessed)} and "
            "re-run; until then fairness for it is untested, not passed."
            if unassessed
            else "Re-run on each release and on production samples."
        ),
        metrics=metrics | {"unassessed_attributes": unassessed},
        details={"attributes": per_attr},
    )


@register(
    "fairness.intersectional",
    title="Intersectional fairness",
    category="Fairness",
    system_types=("tabular_classifier",),
    order=21,
)
def intersectional(ctx: AuditContext) -> CheckResult:
    di_min = ctx.spec.threshold("disparate_impact_min")
    min_n = int(ctx.spec.threshold("min_group_size"))
    attrs = _present_attributes(ctx)
    if len(attrs) < 2:
        raise MissingArtifact("Intersectional analysis needs at least two sensitive features")

    df = ctx.eval_df
    pairs = {}
    worst_pair, worst_di = None, float("inf")
    for a, b in combinations(attrs, 2):
        combo = df[a].astype(str) + " × " + df[b].astype(str)
        rows = group_table(combo, ctx.eval_y, ctx.eval_pred, ctx.eval_scores, min_n)
        summary = parity_summary(rows)
        marginals = [
            parity_summary(group_table(df[x], ctx.eval_y, ctx.eval_pred, ctx.eval_scores, min_n))
            for x in (a, b)
        ]
        marginal_dis = [m["disparate_impact_ratio"] for m in marginals if assessable(m)]
        summary["marginal_min_di"] = round(min(marginal_dis), 4) if marginal_dis else None
        pairs[f"{a} × {b}"] = {
            "groups": rows,
            "summary": summary,
            "small_subgroups": [r["group"] for r in rows if not r["adequate_sample"]],
        }
        # Only pairs with two or more adequate subgroups count; others were not tested.
        if assessable(summary) and summary["disparate_impact_ratio"] < worst_di:
            worst_pair, worst_di = f"{a} × {b}", summary["disparate_impact_ratio"]

    if worst_pair is None:
        status, severity = Status.WARN, Severity.LOW
        plain = (
            "Intersectional fairness could not be assessed: no combination of attributes had two or "
            "more subgroups large enough to compare."
        )
        summary_text = (
            f"No attribute pair had two or more subgroups with at least {min_n} records, so no "
            "intersectional comparison was possible."
        )
    else:
        s = pairs[worst_pair]["summary"]
        status, severity = _grade(s, di_min, 1.0)
        marginal_min = s["marginal_min_di"]
        hidden = marginal_min is not None and s["disparate_impact_ratio"] < marginal_min - 0.05
        summary_text = (
            f"Worst pair {worst_pair}: DI {s['disparate_impact_ratio']:.2f} between "
            f"'{s['least_favoured']}' and '{s['most_favoured']}' (p={s['p_value']:.3g}); "
            + (
                f"lowest single-attribute DI for the same attributes is {marginal_min:.2f}."
                if marginal_min is not None
                else "the single attributes could not be compared on their own."
            )
            + (
                " The intersectional gap is larger than either attribute shows on its own."
                if hidden
                else ""
            )
        )
        plain = (
            f"The combined group '{s['least_favoured']}' is treated less favourably than any single "
            "attribute reveals."
            if hidden and status != Status.PASS
            else f"The combined group '{s['least_favoured']}' has the lowest favourable-outcome rate."
            if status != Status.PASS
            else "No intersectional subgroup falls below the four-fifths benchmark."
        )

    return CheckResult(
        check_id="fairness.intersectional",
        title="Intersectional fairness",
        category="Fairness",
        status=status,
        severity=severity,
        summary=summary_text,
        plain_summary=plain,
        recommendation=(
            "Report subgroup metrics alongside single-attribute metrics and set an explicit subgroup "
            "tolerance. Collect more data for subgroups below the minimum sample size."
        ),
        metrics={
            "worst_pair": worst_pair,
            "worst_intersectional_di": round(worst_di, 4) if worst_pair else None,
        },
        details={"pairs": pairs},
    )


@register(
    "fairness.proxy_features",
    title="Proxy-feature screening",
    category="Fairness",
    system_types=("tabular_classifier",),
    order=22,
)
def proxy_features(ctx: AuditContext) -> CheckResult:
    limit = ctx.spec.threshold("proxy_auc_max")
    attrs = _present_attributes(ctx)
    X = ctx.X(ctx.eval_df)
    direct = [a for a in ctx.spec.sensitive_features if a in ctx.feature_columns]
    allow_direct = bool(
        ctx.spec.check_options("fairness.proxy_features").get("allow_sensitive_inputs")
    )

    findings = []
    matrix: dict[str, dict[str, float]] = {}
    for feature in X.columns:
        matrix[feature] = {}
        for attr in attrs:
            if feature == attr:
                continue
            strength = proxy_strength(X[feature], ctx.eval_df[attr])
            matrix[feature][attr] = round(strength, 4)
            if strength > limit:
                findings.append({"feature": feature, "attribute": attr, "auc": round(strength, 4)})
    findings.sort(key=lambda f: -f["auc"])

    if direct and not allow_direct:
        status, severity = Status.FAIL, Severity.CRITICAL
    elif any(f["auc"] > 0.85 for f in findings):
        status, severity = Status.FAIL, Severity.HIGH
    elif findings:
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    listed = ", ".join(
        f"{f['feature']}→{f['attribute']} (AUC {f['auc']:.2f})" for f in findings[:5]
    )
    summary = (
        f"Protected attributes used directly as inputs: {', '.join(direct)}. " if direct else ""
    ) + (
        f"{len(findings)} feature/attribute pairs exceed proxy AUC {limit}: {listed}."
        if findings
        else f"No input predicts a protected attribute with AUC above {limit}."
    )
    plain = (
        f"Some inputs (e.g. '{findings[0]['feature']}') closely track '{findings[0]['attribute']}', so "
        "the model can discriminate indirectly even though that attribute is excluded."
        if findings
        else "No input closely tracks a protected attribute."
    )
    if direct and not allow_direct:
        plain = f"The model uses protected attributes ({', '.join(direct)}) directly as inputs."

    return CheckResult(
        check_id="fairness.proxy_features",
        title="Proxy-feature screening",
        category="Fairness",
        status=status,
        severity=severity,
        summary=summary,
        plain_summary=plain,
        recommendation=(
            "For each flagged feature, document a business justification, test model variants without "
            "it, and compare fairness and performance. Remove protected attributes from inputs unless a "
            "documented legal basis allows them."
        ),
        metrics={"flagged_pairs": len(findings), "direct_sensitive_inputs": len(direct)},
        details={"flagged": findings, "matrix": matrix},
    )
