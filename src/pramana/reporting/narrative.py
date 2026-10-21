"""Plain-English executive summary for non-technical readers."""

from __future__ import annotations

from typing import Any

from pramana.types import Severity, Status

TIER_TEXT = {
    "prohibited": "a prohibited practice under the EU AI Act",
    "high": "high-risk under the EU AI Act",
    "limited": "subject to EU AI Act transparency duties",
    "gpai": "a general-purpose AI model under the EU AI Act",
    "minimal": "minimal-risk under the EU AI Act",
}


def executive_summary(result) -> dict[str, Any]:
    """Build the headline, key messages and decisions needed from an AuditResult."""
    spec = result.spec
    cls = result.classification
    open_risks = [r for r in result.risks if not r.accepted]
    serious = [r for r in open_risks if r.rating.rank >= Severity.HIGH.rank]
    applicable = sum(1 for c in result.coverage["controls"] if c["state"] != "not applicable")
    evidenced = sum(1 for c in result.coverage["controls"] if c["state"] == "evidenced")

    incomplete = result.gate.get("incomplete_checks", [])
    if result.gate["decision"] == "BLOCK" and incomplete and not serious:
        headline = (
            f"Release is blocked: {len(incomplete)} test{'s' if len(incomplete) != 1 else ''} could not "
            f"be completed for {spec.name} v{spec.system['version']}, so the audit cannot vouch for it yet."
        )
    elif result.gate["decision"] == "BLOCK":
        headline = (
            f"Release is blocked: {len(serious)} high or critical "
            f"{'risks need' if len(serious) != 1 else 'risk needs'} treatment before {spec.name} "
            f"v{spec.system['version']} goes live."
        )
    else:
        headline = (
            f"{spec.name} v{spec.system['version']} can be released; "
            f"{len(open_risks)} lower-rated finding{'s' if len(open_risks) != 1 else ''} remain open."
        )

    by_check = {r.check_id: r for r in result.results}
    key_findings = []
    for risk in sorted(open_risks, key=lambda r: (-r.score, r.risk_id))[:5]:
        check = by_check.get(risk.source_check)
        key_findings.append(
            {
                "risk_id": risk.risk_id,
                "rating": risk.rating.value,
                "text": check.plain_summary if check else risk.description,
                "owner": risk.owner,
            }
        )

    working = [
        r.plain_summary
        for r in result.results
        if r.status == Status.PASS and r.plain_summary and r.check_id not in ("audit.process",)
    ][:3]

    tier = cls.get("eu_tier", "minimal")
    context = (
        f"This system is {TIER_TEXT.get(tier, tier)}"
        + ("" if cls.get("eu_applicable") else " (used as a benchmark; no EU deployment declared)")
        + f", and its India context sensitivity is {cls.get('india_sensitivity', 'n/a')}."
    )
    upcoming = [o for o in cls.get("obligations", []) if o["status"] == "upcoming"]
    if upcoming:
        nxt = upcoming[0]
        context += (
            f" Next milestone: {nxt['obligation']} ({nxt['date']}, {nxt['days_remaining']} days)."
        )

    decisions = []
    for item in result.remediation[:4]:
        decisions.append(
            f"{item['owner']}: {item['action'].split('. ')[0].rstrip('.')} (by {item['due']})"
        )
    for risk in result.risks:
        if risk.accepted and risk.acceptance:
            decisions.append(
                f"Accepted risk {risk.risk_id} ({risk.title}) expires {risk.acceptance.get('expires')}; "
                f"re-approval needed from {risk.acceptance.get('approved_by')}."
            )

    return {
        "headline": headline,
        "context": context,
        "key_findings": key_findings,
        "working": working,
        "decisions": decisions,
        "coverage_line": (
            f"{evidenced} of {applicable} applicable controls across "
            f"{sum(1 for fw in result.coverage['frameworks'].values() if sum(fw['totals'][s] for s in ('evidenced', 'partial', 'deficient', 'not tested')))} "
            "frameworks are evidenced by this audit. Controls marked 'not tested' need "
            "organisational evidence (policies, records, sign-offs) that tests cannot produce."
        ),
    }
