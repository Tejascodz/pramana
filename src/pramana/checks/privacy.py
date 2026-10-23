"""Personal-data exposure in datasets and membership-inference risk of the model."""

from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd

from pramana.context import AuditContext, MissingArtifact
from pramana.metrics import safe_auc
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "india_mobile": re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b"),
    "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "aadhaar_like": re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "card_like": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}
NAME_HINTS = ("name", "email", "phone", "mobile", "address", "aadhaar", "pan_no", "passport", "dob")
SAMPLE = 500
MIN_MATCH_RATE = 0.30


def _luhn_ok(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            d = d - 9 if d > 9 else d
        total += d
    return total % 10 == 0


def scan_frame(df: pd.DataFrame, dataset: str) -> list[dict[str, Any]]:
    """Return columns that look like they hold direct identifiers."""
    hits = []
    for col in df.columns:
        series = df[col].dropna()
        hint = any(h in col.lower() for h in NAME_HINTS)
        if series.empty:
            continue
        sample = series.astype(str).head(SAMPLE)
        best_kind, best_rate = None, 0.0
        if not pd.api.types.is_float_dtype(series):
            for kind, pattern in PII_PATTERNS.items():
                matches = sample.str.contains(pattern).astype(bool)
                if kind == "card_like":
                    matches = pd.Series(
                        [bool(m) and _luhn_ok(v) for v, m in zip(sample, matches, strict=True)],
                        index=sample.index,
                    )
                match_rate = float(matches.mean())
                if match_rate > best_rate:
                    best_kind, best_rate = kind, match_rate
        if best_rate >= MIN_MATCH_RATE or (hint and best_rate > 0):
            hits.append(
                {
                    "dataset": dataset,
                    "column": col,
                    "kind": best_kind,
                    "match_rate": round(best_rate, 3),
                }
            )
        elif hint and pd.api.types.is_object_dtype(series):
            hits.append(
                {"dataset": dataset, "column": col, "kind": "name_hint", "match_rate": None}
            )
    return hits


@register(
    "privacy.pii_exposure",
    title="Personal-data exposure",
    category="Privacy",
    system_types=("tabular_classifier",),
    order=60,
)
def pii_exposure(ctx: AuditContext) -> CheckResult:
    allowed = set(ctx.spec.check_options("privacy.pii_exposure").get("allowed_columns", []))
    frames = {
        "evaluation_data": ctx.eval_df,
        "reference_data": ctx.ref_df,
        "production_data": ctx.prod_df,
    }
    hits = []
    for name, frame in frames.items():
        if frame is not None:
            hits.extend(h for h in scan_frame(frame, name) if h["column"] not in allowed)

    in_model = sorted({h["column"] for h in hits if h["column"] in ctx.feature_columns})
    columns = sorted({h["column"] for h in hits})
    if in_model:
        status, severity = Status.FAIL, Severity.CRITICAL
    elif hits:
        status, severity = Status.FAIL, Severity.HIGH
    else:
        status, severity = Status.PASS, Severity.INFO

    summary = (
        f"Direct identifiers found in {len(columns)} column(s): "
        + ", ".join(f"{h['column']} [{h['kind']}] in {h['dataset']}" for h in hits[:6])
        + "."
        + (
            f" Used as model inputs: {', '.join(in_model)}."
            if in_model
            else " None are model inputs."
        )
        if hits
        else "No direct identifiers detected in any dataset supplied for the audit."
    )
    return CheckResult(
        check_id="privacy.pii_exposure",
        title="Personal-data exposure",
        category="Privacy",
        status=status,
        severity=severity,
        summary=summary,
        plain_summary=(
            f"Datasets used for modelling contain personal contact details ({', '.join(columns)}) that "
            "the model does not need."
            if hits and not in_model
            else "The model takes personal identifiers as inputs."
            if in_model
            else "No personal identifiers were found in the modelling data."
        ),
        recommendation=(
            "Drop or pseudonymise identifier columns before data reaches modelling and evaluation "
            "environments, and record the purpose and lawful basis for any personal data retained "
            "(DPDP Act 2023 purpose limitation and data minimisation)."
        ),
        metrics={"identifier_columns": len(columns), "identifiers_in_model_inputs": len(in_model)},
        details={"hits": hits},
    )


def _per_sample_loss(y: np.ndarray, p: np.ndarray) -> np.ndarray:
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return -(y * np.log(p) + (1 - y) * np.log(1 - p))


@register(
    "privacy.membership_inference",
    title="Membership-inference risk",
    category="Privacy",
    system_types=("tabular_classifier",),
    order=61,
)
def membership_inference(ctx: AuditContext) -> CheckResult:
    if ctx.ref_df is None or ctx.spec.target not in ctx.ref_df.columns:
        raise MissingArtifact("Membership inference needs labelled training data as reference_data")
    limit = ctx.spec.threshold("mia_auc_max")
    members, non_members = ctx.ref_df, ctx.eval_df
    n = min(len(members), len(non_members), 5000)
    members = members.sample(n, random_state=ctx.spec.seed)
    non_members = non_members.sample(n, random_state=ctx.spec.seed)

    loss_in = _per_sample_loss(ctx.y(members), ctx.score(members))
    loss_out = _per_sample_loss(ctx.y(non_members), ctx.score(non_members))
    labels = np.r_[np.ones(n), np.zeros(n)]
    attack_auc = safe_auc(labels, -np.r_[loss_in, loss_out])
    advantage = 2 * (attack_auc - 0.5)
    # An average AUC can hide an attack that is very confident about a few records.
    # Carlini et al. (IEEE S&P 2022) recommend reporting the true-positive rate at a low
    # false-positive rate; here for the same loss-threshold attack, at 1% and 5% FPR.
    tail = {}
    for fpr in (0.01, 0.05):
        if n * fpr >= 1:
            cut = float(np.quantile(loss_out, fpr))
            tail[fpr] = round(float((loss_in <= cut).mean()), 4)
        else:
            tail[fpr] = None

    if attack_auc > limit + 0.10:
        status, severity = Status.FAIL, Severity.HIGH
    elif attack_auc > limit:
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    return CheckResult(
        check_id="privacy.membership_inference",
        title="Membership-inference risk",
        category="Privacy",
        status=status,
        severity=severity,
        summary=(
            f"Loss-threshold attack (Yeom et al., 2018) on {n} training and {n} held-out rows: attack AUC "
            f"{attack_auc:.3f} (limit {limit}), membership advantage {advantage:.3f}. Mean loss "
            f"{loss_in.mean():.3f} on training rows vs {loss_out.mean():.3f} on held-out rows."
            + (
                f" At a 1% false-positive rate the attack identifies {tail[0.01]:.1%} of training "
                f"rows (5% FPR: {tail[0.05]:.1%})."
                if tail[0.01] is not None and tail[0.05] is not None
                else ""
            )
        ),
        plain_summary=(
            "An attacker could tell whether a specific person was in the training data more often than chance."
            if status != Status.PASS
            else "The model does not reveal who was in its training data beyond chance level."
        ),
        recommendation=(
            "Reduce overfitting (regularisation, fewer trees, early stopping) or train with differential "
            "privacy, then re-run this test."
        ),
        metrics={
            "attack_auc": round(attack_auc, 4),
            "membership_advantage": round(advantage, 4),
            "tpr_at_1pct_fpr": tail[0.01],
            "tpr_at_5pct_fpr": tail[0.05],
        },
    )
