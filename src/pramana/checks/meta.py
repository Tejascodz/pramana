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
    if attrs:
        attr = attrs[0]
        groups = df[attr].astype(str)
        target_group = groups.value_counts().index[0]
        pred = ctx.eval_pred.copy()
        idx = np.where((groups == target_group).to_numpy() & (pred == 1))[0]
        flip = rng.choice(idx, size=int(len(idx) * 0.5), replace=False) if len(idx) else idx
        pred[flip] = 0
        summary = parity_summary(
            group_table(
                groups, ctx.eval_y, pred, ctx.eval_scores, int(ctx.spec.threshold("min_group_size"))
            )
        )
        di = summary.get("disparate_impact_ratio", 1.0)
        canaries.append(
            {
                "canary": f"halve favourable decisions for {attr}={target_group}",
                "detected": bool(di < ctx.spec.threshold("disparate_impact_min")),
                "observed": f"DI {di:.2f}",
            }
        )

    numeric = ctx.numeric_features
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

    planted = pd.DataFrame(
        {"contact": [f"user{i}@example.org" for i in range(50)], "noise": rng.normal(size=50)}
    )
    canaries.append(
        {
            "canary": "plant an email column in a copy of the data",
            "detected": any(h["column"] == "contact" for h in scan_frame(planted, "canary")),
            "observed": "scanner run on planted column",
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
            f"{len(canaries) - len(missed)}/{len(canaries)} planted defects detected. "
            + "; ".join(f"{c['canary']}: {c['observed']}" for c in canaries)
            + "."
        ),
        plain_summary=(
            "The audit tests caught every defect deliberately planted to check them."
            if not missed
            else "Some audit tests missed defects that were deliberately planted, so their results need review."
        ),
        recommendation="Tune thresholds or test design for any canary that was missed before relying on results.",
        metrics={"canaries": len(canaries), "missed": len(missed)},
        details={"canaries": canaries},
    )
