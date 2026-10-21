"""Turn check findings into a scored risk register and a release-gate decision."""

from __future__ import annotations

from datetime import date
from typing import Any

from pramana.types import CheckResult, Risk, Severity, Status

IMPACT_BY_SEVERITY = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
LIKELIHOOD_BY_STATUS = {Status.FAIL: 4, Status.WARN: 3}
HIGH_STAKES_TIERS = {"high", "prohibited"}
RIGHTS_CATEGORIES = {"Fairness", "Privacy", "Accountability", "Transparency"}

OWNER_BY_CATEGORY = {
    "Fairness": "risk_owner",
    "Privacy": "data_protection_officer",
    "Security": "security_owner",
    "Governance": "approver",
    "Transparency": "model_owner",
    "Accountability": "risk_owner",
}


def _owner(category: str, raci: dict[str, str]) -> str:
    role = OWNER_BY_CATEGORY.get(category, "model_owner")
    return raci.get(role) or raci.get("model_owner") or "Unassigned"


def _acceptance_for(
    check_id: str, acceptances: list[dict[str, Any]], today: date
) -> dict[str, Any] | None:
    for acc in acceptances:
        if acc.get("check") != check_id:
            continue
        expires = acc.get("expires")
        if expires and date.fromisoformat(str(expires)) < today:
            continue
        if not acc.get("approved_by") or not acc.get("justification"):
            continue
        return acc
    return None


def build_register(
    results: list[CheckResult],
    *,
    eu_tier: str,
    raci: dict[str, str],
    acceptances: list[dict[str, Any]],
    today: date,
) -> list[Risk]:
    risks = []
    scored = []
    for result in (r for r in results if r.status.is_finding):
        impact = IMPACT_BY_SEVERITY[result.severity]
        # In high-risk uses, medium findings that touch people's rights carry high impact.
        if (
            eu_tier in HIGH_STAKES_TIERS
            and result.severity == Severity.MEDIUM
            and result.category in RIGHTS_CATEGORIES
        ):
            impact += 1
        likelihood = LIKELIHOOD_BY_STATUS[result.status]
        acceptance = _acceptance_for(result.check_id, acceptances, today)
        scored.append(
            Risk(
                risk_id="",
                title=result.title,
                description=result.plain_summary or result.summary,
                source_check=result.check_id,
                likelihood=likelihood,
                impact=impact,
                owner=_owner(result.category, raci),
                treatment="Accept (approved)" if acceptance else "Mitigate",
                recommendation=result.recommendation,
                controls=result.controls,
                accepted=acceptance is not None,
                acceptance=acceptance,
            )
        )
    scored.sort(key=lambda r: (r.accepted, -r.score, -r.impact, r.source_check))
    for i, risk in enumerate(scored, 1):
        risk.risk_id = f"R-{i:02d}"
        risks.append(risk)
    return risks


def gate_decision(
    risks: list[Risk], gate: dict[str, Any], incomplete: list[str] | None = None
) -> dict[str, Any]:
    """BLOCK if any open risk is in ``block_on``, or if a check could not complete.

    An audit that could not run a test cannot vouch for that control, so errored
    checks block release unless ``gate.allow_incomplete`` is set.
    """
    block_on = {Severity(s) for s in gate.get("block_on", ["critical", "high"])}
    blocking = [r for r in risks if not r.accepted and r.rating in block_on]
    accepted = [r for r in risks if r.accepted]
    incomplete = list(incomplete or [])
    blocked_by_incomplete = bool(incomplete) and not gate.get("allow_incomplete", False)
    return {
        "decision": "BLOCK" if blocking or blocked_by_incomplete else "PASS",
        "block_on": sorted(s.value for s in block_on),
        "blocking_risks": [r.risk_id for r in blocking],
        "accepted_risks": [r.risk_id for r in accepted],
        "incomplete_checks": incomplete,
    }


def audit_opinion(risks: list[Risk], incomplete: list[str] | None = None) -> dict[str, str]:
    """Overall rating in the style of an internal-audit report."""
    open_risks = [r for r in risks if not r.accepted]
    worst = max((r.rating for r in open_risks), key=lambda s: s.rank, default=Severity.INFO)
    if incomplete and worst.rank < Severity.HIGH.rank:
        return {
            "rating": "Incomplete",
            "statement": f"{len(incomplete)} test(s) could not be completed, so no opinion can be given on the controls they cover. Re-run once the inputs or endpoint are available.",
        }
    if worst.rank >= Severity.HIGH.rank:
        return {
            "rating": "Ineffective",
            "statement": "Controls over this AI system do not yet manage its key risks. Release should wait for remediation of high and critical findings.",
        }
    if worst.rank >= Severity.MEDIUM.rank:
        return {
            "rating": "Partially effective",
            "statement": "Key controls operate, but medium-rated findings need remediation within an agreed timeline.",
        }
    return {
        "rating": "Effective",
        "statement": "Controls tested operate as intended. Remaining observations are low priority.",
    }
