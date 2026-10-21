"""Stability of decisions under input noise, missing values and monotonic expectations."""

from __future__ import annotations

from typing import Any

import numpy as np

from pramana.context import AuditContext, MissingArtifact
from pramana.metrics import safe_auc
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status

NOISE_LEVELS = (0.01, 0.05, 0.10)


@register(
    "robustness.perturbation",
    title="Robustness to perturbation",
    category="Robustness",
    system_types=("tabular_classifier",),
    order=30,
)
def perturbation(ctx: AuditContext) -> CheckResult:
    if not ctx.has_model:
        raise MissingArtifact("Perturbation testing needs the model, not just scores")
    max_flip = ctx.spec.threshold("noise_flip_rate_max")
    options = ctx.spec.check_options("robustness.perturbation")
    df = ctx.eval_df
    numeric = ctx.numeric_features
    if not numeric:
        raise MissingArtifact("No numeric model inputs to perturb")

    base_pred = ctx.eval_pred
    stds = df[numeric].std().replace(0, 1.0)
    noise_results: list[dict[str, Any]] = []
    for level in NOISE_LEVELS:
        noisy = df.copy()
        noise = ctx.rng.normal(0.0, 1.0, size=(len(df), len(numeric))) * stds.to_numpy() * level
        noisy[numeric] = df[numeric].to_numpy(dtype=float) + noise
        scores = ctx.score(noisy)
        noise_results.append(
            {
                "noise_sigma": level,
                "flip_rate": round(float((ctx.decide(scores) != base_pred).mean()), 4),
                "auc": round(safe_auc(ctx.eval_y, scores), 4),
            }
        )

    missing_ok, missing_flip = True, None
    try:
        holed = df.copy()
        mask = ctx.rng.random((len(df), len(numeric))) < 0.10
        values = holed[numeric].to_numpy(dtype=float)
        values[mask] = np.nan
        holed[numeric] = values
        missing_flip = round(float((ctx.decide(ctx.score(holed)) != base_pred).mean()), 4)
    except Exception:  # noqa: BLE001 - any failure here is itself the finding
        missing_ok = False

    monotonic: list[dict[str, Any]] = []
    for direction in ("increasing", "decreasing"):
        for feature in options.get(f"monotone_{direction}", []):
            if feature not in numeric:
                continue
            bumped = df.copy()
            bumped[feature] = df[feature] + stds[feature]
            delta = ctx.score(bumped) - ctx.eval_scores
            wrong = (delta < -1e-9) if direction == "increasing" else (delta > 1e-9)
            monotonic.append(
                {
                    "feature": feature,
                    "expected": direction,
                    "violation_rate": round(float(wrong.mean()), 4),
                }
            )

    small, medium = noise_results[0]["flip_rate"], noise_results[1]["flip_rate"]
    bad_mono = [m for m in monotonic if m["violation_rate"] > 0.05]
    if small > max_flip:
        status, severity = Status.FAIL, Severity.HIGH
    elif medium > max_flip or not missing_ok or bad_mono:
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    parts = [
        f"Decision flip rate {small:.1%} at 1% noise, {medium:.1%} at 5%, "
        f"{noise_results[2]['flip_rate']:.1%} at 10% of each feature's std (limit {max_flip:.0%})."
    ]
    parts.append(
        f"10% missing numeric values flip {missing_flip:.1%} of decisions."
        if missing_ok
        else "The model raised an error when numeric inputs were missing."
    )
    for m in monotonic:
        parts.append(
            f"{m['feature']} should be {m['expected']}: violated for {m['violation_rate']:.1%} of rows."
        )

    plain = (
        "Tiny changes to applicant data can change the decision, so outcomes are not reliably repeatable."
        if status == Status.FAIL
        else "Decisions stay stable under small input changes"
        + ("; some business-logic expectations are violated." if bad_mono else ".")
    )
    return CheckResult(
        check_id="robustness.perturbation",
        title="Robustness to perturbation",
        category="Robustness",
        status=status,
        severity=severity,
        summary=" ".join(parts),
        plain_summary=plain,
        recommendation=(
            "Add input validation and imputation, apply monotonic constraints where the business logic "
            "requires them, and add a manual-review band around the decision threshold."
        ),
        metrics={
            "flip_rate_1pct": small,
            "flip_rate_5pct": medium,
            "flip_rate_10pct": noise_results[2]["flip_rate"],
            "missing_value_flip_rate": missing_flip,
            "handles_missing": missing_ok,
        },
        details={"noise": noise_results, "monotonicity": monotonic},
    )
