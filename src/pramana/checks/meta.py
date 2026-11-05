"""Detector sensitivity: does the audit itself catch defects that are known to exist?

Each canary plants a defect of known size into a copy of the evaluation data and
confirms the matching test flags it. A test that cannot catch a planted defect
gives false assurance, which is what NIST AI RMF MEASURE 2.13 asks auditors to rule out.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from pramana.checks.drift import feature_drift
from pramana.checks.fairness import group_table, parity_summary
from pramana.checks.privacy import scan_frame
from pramana.context import AuditContext, MissingArtifact
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status


@register(
    "audit.detector_sensitivity",
    title="Audit self-test (canaries)",
    category="Assurance",
    system_types=("tabular_classifier",),
    order=90,
)
def detector_sensitivity(ctx: AuditContext) -> CheckResult:
    df = ctx.eval_df
    rng = np.random.default_rng(ctx.spec.seed + 1)
    canaries = []

    attrs = [a for a in ctx.spec.sensitive_features if a in df.columns]
    di_min = ctx.spec.threshold("disparate_impact_min")
    if attrs:
        attr = attrs[0]
        groups = df[attr].astype(str)
        min_n = int(ctx.spec.threshold("min_group_size"))
        base = [
            r
            for r in group_table(groups, ctx.eval_y, ctx.eval_pred, ctx.eval_scores, min_n)
            if r["adequate_sample"]
        ]
        # Planted on a balanced copy, not on the model's own decisions: on real decisions a gap
        # that already exists would make the canary look detected even if nothing was planted
        # (for example when the least-favoured group has no favourable decision to remove).
        if len(base) >= 2:
            names = [r["group"] for r in base]
            mask = groups.isin(names).to_numpy()
            g = groups.to_numpy()[mask]
            y, scores = ctx.eval_y[mask], ctx.eval_scores[mask]
            balanced = np.zeros(len(g), dtype=int)
            for name in names:
                idx = rng.permutation(np.where(g == name)[0])
                balanced[idx[: round(0.6 * len(idx))]] = 1
            control = parity_summary(group_table(pd.Series(g), y, balanced, scores, min_n))
            target = max(base, key=lambda r: r["n"])["group"]
            planted = balanced.copy()
            positives = rng.permutation(np.where((g == target) & (planted == 1))[0])
            flipped = positives[: len(positives) // 2]
            planted[flipped] = 0
            summary = parity_summary(group_table(pd.Series(g), y, planted, scores, min_n))
            di = summary.get("disparate_impact_ratio")
            di0 = control.get("disparate_impact_ratio")
            ok_di = di is not None and not np.isnan(di)
            ok_di0 = di0 is not None and not np.isnan(di0)
            canaries.append(
                {
                    "canary": f"balanced copy, then halve favourable decisions for {attr}={target}",
                    "detected": bool(len(flipped) > 0 and ok_di and di < di_min),
                    "observed": (f"DI {di:.2f}" if ok_di else "DI not computable")
                    + f" after {len(flipped)} decisions flipped",
                }
            )
            canaries.append(
                {
                    "canary": f"balanced copy of {attr} is not flagged (false-alarm control)",
                    "detected": bool(ok_di0 and di0 >= di_min),
                    "observed": f"DI {di0:.2f}" if ok_di0 else "DI not computable",
                    "control": True,
                }
            )

    # A constant or empty column cannot show a shift, so plant the drift canary in the first
    # numeric feature that actually varies.
    numeric = [c for c in ctx.numeric_features if df[c].dropna().nunique() > 1]
    if numeric:
        col = numeric[0]
        shifted = df.copy()
        shifted[col] = shifted[col] + 1.5 * shifted[col].std()
        psi = feature_drift(df, shifted, [col])[0]["psi"]
        canaries.append(
            {
                "canary": f"shift {col} by 1.5 standard deviations",
                "detected": bool(psi >= ctx.spec.threshold("psi_fail")),
                "observed": f"PSI {psi:.2f}",
            }
        )
        if len(df) >= 400:
            # Two random halves of the same data come from one distribution: flagging them
            # would mean the drift test raises false alarms at this sample size.
            order = rng.permutation(len(df))
            half_a, half_b = df.iloc[order[: len(df) // 2]], df.iloc[order[len(df) // 2 :]]
            psi0 = feature_drift(half_a, half_b, [col])[0]["psi"]
            canaries.append(
                {
                    "canary": f"two random halves of the data on {col} (false-alarm control)",
                    "detected": bool(not np.isnan(psi0) and psi0 < ctx.spec.threshold("psi_fail")),
                    "observed": f"PSI {psi0:.2f}",
                    "control": True,
                }
            )

    # Sparse e-mail addresses in a column whose name gives no hint, beside a column of plain
    # references that must not be flagged.
    contact = [f"ref-{i}" for i in range(95)] + [f"user{i}@example.org" for i in range(5)]
    planted = pd.DataFrame({"col_a": contact, "col_b": [f"CUST-{i:05d}" for i in range(100)]})
    flagged = {h["column"] for h in scan_frame(planted, "canary")}
    canaries.append(
        {
            "canary": "plant 5 e-mail addresses in 100 values of an unnamed column",
            "detected": "col_a" in flagged,
            "observed": "scanner run on planted column",
        }
    )
    canaries.append(
        {
            "canary": "a column of customer references is not flagged (false-alarm control)",
            "detected": "col_b" not in flagged,
            "observed": "flagged" if "col_b" in flagged else "not flagged",
            "control": True,
        }
    )

    if not canaries:
        raise MissingArtifact("No canaries could be planted for this dataset")
    missed = [c for c in canaries if not c["detected"]]
    status = Status.FAIL if missed else Status.PASS
    return CheckResult(
        check_id="audit.detector_sensitivity",
        title="Audit self-test (canaries)",
        category="Assurance",
        status=status,
        severity=Severity.HIGH if missed else Severity.INFO,
        summary=(
            f"{len(canaries) - len(missed)}/{len(canaries)} self-tests passed "
            f"({sum(1 for c in canaries if not c.get('control'))} planted defects, "
            f"{sum(1 for c in canaries if c.get('control'))} false-alarm controls). "
            + "; ".join(f"{c['canary']}: {c['observed']}" for c in canaries)
            + "."
        ),
        plain_summary=(
            "The audit tests caught every defect deliberately planted to check them, and raised "
            "no alarm on clean copies."
            if not missed
            else "Some audit tests missed a planted defect or raised a false alarm on clean data, so "
            "their results need review."
        ),
        recommendation="Tune thresholds or test design for any canary that was missed before relying on results.",
        metrics={"canaries": len(canaries), "missed": len(missed)},
        details={"canaries": canaries},
    )
