"""Model documentation completeness and reconciliation of documented claims with evidence."""

from __future__ import annotations

from typing import Any

from pramana.context import AuditContext, MissingArtifact
from pramana.metrics import safe_auc
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status

# Fields drawn from Model Cards (Mitchell et al., 2019) plus what the EU AI Act
# (Art. 11, 13, 14 and Annex IV) and ISO/IEC 42001 A.6.2.7 expect to be documented.
REQUIRED_FIELDS: dict[str, str] = {
    "model_details.name": "Model name",
    "model_details.version": "Version",
    "model_details.owner": "Accountable owner",
    "model_details.date": "Release date",
    "intended_use.primary_uses": "Intended uses",
    "intended_use.primary_users": "Intended users",
    "intended_use.out_of_scope_uses": "Out-of-scope uses",
    "factors.relevant_groups": "Groups considered in evaluation",
    "metrics.performance_measures": "Performance measures",
    "metrics.decision_threshold": "Decision threshold",
    "training_data.description": "Training data description",
    "training_data.provenance": "Training data provenance",
    "evaluation_data.description": "Evaluation data description",
    "ethical_considerations": "Ethical considerations",
    "caveats_and_limitations": "Limitations",
    "human_oversight.measures": "Human oversight measures",
    "human_oversight.override_process": "Override / appeal process",
    "contact.escalation": "Escalation contact",
    "impact_assessment.reference": "Impact assessment reference",
    "key_drivers": "Expected key drivers",
}


TABULAR_ONLY = {"metrics.decision_threshold", "key_drivers"}


def _lookup(doc: dict[str, Any], dotted: str) -> Any:
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _filled(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().upper() not in {"TBD", "TODO", "N/A"}
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return True


@register(
    "documentation.model_card",
    title="Documentation and claims",
    category="Transparency",
    system_types=("tabular_classifier", "llm_application", "agent"),
    order=70,
)
def model_card(ctx: AuditContext) -> CheckResult:
    doc = ctx.documentation
    if doc is None:
        raise MissingArtifact("artifacts.documentation (model card YAML) was not supplied")

    min_complete = ctx.spec.threshold("model_card_min_completeness")
    required = {
        k: v
        for k, v in REQUIRED_FIELDS.items()
        if ctx.spec.system_type == "tabular_classifier" or k not in TABULAR_ONLY
    }
    missing = [label for key, label in required.items() if not _filled(_lookup(doc, key))]
    completeness = 1 - len(missing) / len(required)

    mismatches = []
    documented_threshold = _lookup(doc, "metrics.decision_threshold")
    if documented_threshold is not None and ctx.spec.system_type == "tabular_classifier":
        if abs(float(documented_threshold) - ctx.spec.decision_threshold) > 1e-9:
            mismatches.append(
                f"documented threshold {documented_threshold} differs from deployed "
                f"{ctx.spec.decision_threshold}"
            )
    claimed = _lookup(doc, "metrics.claimed") or {}
    if "auc" in claimed and ctx.spec.system_type == "tabular_classifier":
        measured = safe_auc(ctx.eval_y, ctx.eval_scores)
        if float(claimed["auc"]) - measured > 0.02:
            mismatches.append(f"documented AUC {claimed['auc']} but measured {measured:.3f}")

    if completeness < 0.6:
        status, severity = Status.FAIL, Severity.HIGH
    elif mismatches:
        status, severity = Status.FAIL, Severity.MEDIUM
    elif completeness < min_complete:
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    summary = f"Documentation completeness {completeness:.0%} ({len(required) - len(missing)}/{len(required)} fields)."
    if missing:
        summary += f" Missing: {', '.join(missing)}."
    if mismatches:
        summary += " Claims that do not match evidence: " + "; ".join(mismatches) + "."

    plain = (
        "The documentation overstates or contradicts what the audit measured."
        if mismatches
        else f"Key documentation is missing ({', '.join(missing[:3])})."
        if missing
        else "The system is documented well enough for users and reviewers."
    )
    return CheckResult(
        check_id="documentation.model_card",
        title="Documentation and claims",
        category="Transparency",
        status=status,
        severity=severity,
        summary=summary,
        plain_summary=plain,
        recommendation=(
            "Complete the missing sections, correct documented figures to match validated results, and "
            "make the model card part of the release checklist."
        ),
        metrics={"completeness": round(completeness, 3), "claim_mismatches": len(mismatches)},
        details={"missing": missing, "mismatches": mismatches},
    )
