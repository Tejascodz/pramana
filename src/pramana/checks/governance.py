"""Use-case risk classification, compared with the classification the owner declared."""

from __future__ import annotations

from pramana.context import AuditContext
from pramana.controls import load_library
from pramana.registry import register
from pramana.risk.classification import TIER_ORDER, classify, obligations
from pramana.types import CheckResult, Severity, Status


@register(
    "governance.risk_classification",
    title="Risk classification",
    category="Governance",
    system_types=("tabular_classifier", "llm_application", "agent"),
    order=1,
)
def risk_classification(ctx: AuditContext) -> CheckResult:
    use_case = ctx.spec.use_case
    result = classify(use_case, ctx.spec.system_type)
    result.obligations = obligations(result, use_case, load_library(), ctx.audit_date)
    declared = use_case.get("declared_eu_tier")

    if result.eu_tier == "prohibited":
        status, severity = Status.FAIL, Severity.CRITICAL
        verdict = "The declared use falls under a prohibited practice."
    elif declared and declared not in TIER_ORDER:
        status, severity = Status.WARN, Severity.LOW
        verdict = f"Declared tier '{declared}' is not a recognised tier."
    elif declared and TIER_ORDER.index(declared) < TIER_ORDER.index(result.eu_tier):
        status, severity = Status.FAIL, Severity.HIGH
        verdict = (
            f"The owner declared '{declared}', lower than the assessed '{result.eu_tier}' tier."
        )
    elif not declared:
        status, severity = Status.WARN, Severity.LOW
        verdict = "No risk tier was declared by the system owner."
    else:
        status, severity = Status.PASS, Severity.INFO
        verdict = "Declared and assessed tiers agree."

    scope = (
        "applies" if result.eu_applicable else "is used as a benchmark (no EU deployment declared)"
    )
    upcoming = [o for o in result.obligations if o["status"] == "upcoming"]
    summary = (
        f"EU AI Act tier: {result.eu_tier} ({'; '.join(result.eu_basis)}); the Act {scope}. "
        f"India context sensitivity: {result.india_sensitivity} (score {result.india_score}/10). "
        f"{verdict} {len(upcoming)} upcoming regulatory milestone(s) apply."
    )
    plain = {
        "prohibited": "This use of AI is prohibited in the EU and must not go ahead in that market.",
        "high": "This is a high-risk AI use under the EU AI Act, with strict duties on testing, documentation and human oversight.",
        "limited": "This AI system carries transparency duties: people must know they are dealing with AI.",
        "gpai": "This is a general-purpose AI model with provider obligations.",
        "minimal": "This AI use is minimal-risk under the EU AI Act.",
    }[result.eu_tier]
    if status == Status.FAIL and result.eu_tier != "prohibited":
        plain += " Its owner had classified it lower, so required controls may be missing."

    return CheckResult(
        check_id="governance.risk_classification",
        title="Risk classification",
        category="Governance",
        status=status,
        severity=severity,
        summary=summary,
        plain_summary=plain,
        recommendation=(
            "Record the classification and its basis in the AI inventory, have the accountable executive "
            "sign it off, and plan for each upcoming obligation."
        ),
        metrics={
            "eu_tier": result.eu_tier,
            "declared_eu_tier": declared,
            "india_sensitivity": result.india_sensitivity,
            "upcoming_obligations": len(upcoming),
        },
        details=result.to_dict(),
    )
