"""Risk classification of the use case.

* EU AI Act tier from Art. 5 (prohibited practices), Art. 6 and Annex III
  (high-risk areas) and Art. 50 (transparency).
* An India context-sensitivity rating. The India AI Governance Guidelines call
  for an India-specific, evidence-based risk framework but do not yet define
  tiers, so this rating is a documented Pramana heuristic, not an official tier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Any

from pramana.controls import ControlLibrary

ANNEX_III: dict[str, tuple[str, str]] = {
    "biometric_identification": ("1(a)", "Remote biometric identification"),
    "biometric_categorisation": ("1(b)", "Biometric categorisation by sensitive attributes"),
    "emotion_recognition": ("1(c)", "Emotion recognition"),
    "critical_infrastructure": ("2", "Safety components of critical infrastructure"),
    "education_access": ("3(a)", "Access or admission to education"),
    "education_assessment": ("3(b)", "Evaluating learning outcomes"),
    "exam_proctoring": ("3(d)", "Monitoring prohibited behaviour in tests"),
    "recruitment": ("4(a)", "Recruitment and selection"),
    "worker_management": ("4(b)", "Decisions on promotion, termination, task allocation"),
    "public_benefits": ("5(a)", "Eligibility for public assistance benefits"),
    "credit_scoring": ("5(b)", "Creditworthiness or credit scoring of natural persons"),
    "insurance_pricing": ("5(c)", "Risk assessment and pricing in life and health insurance"),
    "emergency_dispatch": ("5(d)", "Emergency call triage and dispatch"),
    "law_enforcement": ("6", "Law enforcement"),
    "migration_border": ("7", "Migration, asylum and border control"),
    "justice_democracy": ("8", "Administration of justice and democratic processes"),
}

PROHIBITED: dict[str, str] = {
    "manipulative_techniques": "Subliminal, manipulative or deceptive techniques causing significant harm",
    "exploiting_vulnerabilities": "Exploiting vulnerabilities due to age, disability or social situation",
    "social_scoring": "Social scoring leading to detrimental treatment",
    "predictive_policing_profiling": "Crime-risk prediction based solely on profiling",
    "untargeted_face_scraping": "Untargeted scraping of facial images to build recognition databases",
    "emotion_recognition_workplace_education": "Emotion recognition in workplaces or education",
    "biometric_categorisation_sensitive": "Biometric categorisation inferring sensitive characteristics",
    "realtime_remote_biometric_id": "Real-time remote biometric identification in public for law enforcement",
    "non_consensual_intimate_imagery": "Generating non-consensual intimate imagery (Digital Omnibus addition)",
}

ESSENTIAL_DOMAINS = {
    "credit_scoring",
    "insurance_pricing",
    "public_benefits",
    "recruitment",
    "worker_management",
    "education_access",
    "education_assessment",
    "healthcare",
    "housing",
    "customer_support_financial",
}

TIER_ORDER = ["minimal", "limited", "gpai", "high", "prohibited"]


@dataclass
class Classification:
    eu_tier: str
    eu_applicable: bool
    eu_basis: list[str]
    india_sensitivity: str
    india_score: int
    india_factors: list[str]
    sector_notes: list[str]
    obligations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(use_case: dict[str, Any], system_type: str) -> Classification:
    domain = use_case.get("domain", "other")
    regions = {r.upper() for r in use_case.get("deployment_regions", [])}
    flags = set(use_case.get("prohibited_practice_flags", []) or [])
    basis: list[str] = []

    prohibited_hits = sorted(flags & PROHIBITED.keys())
    if prohibited_hits:
        tier = "prohibited"
        basis += [f"Art. 5: {PROHIBITED[f]}" for f in prohibited_hits]
    elif domain in ANNEX_III and not (
        use_case.get("article_6_3_exemption") and not use_case.get("performs_profiling", True)
    ):
        tier = "high"
        point, label = ANNEX_III[domain]
        basis.append(f"Art. 6(2) and Annex III point {point}: {label}")
        if domain == "credit_scoring" and use_case.get("fraud_detection_only"):
            tier = "minimal"
            basis = ["Annex III 5(b) excludes systems used only to detect financial fraud"]
    elif use_case.get("gpai_provider"):
        tier = "gpai"
        basis.append("Provider of a general-purpose AI model (Art. 53)")
    elif use_case.get("interacts_with_people") or use_case.get("generates_synthetic_content"):
        tier = "limited"
        basis.append("Art. 50 transparency: interacts with people or generates synthetic content")
    else:
        tier = "minimal"
        basis.append("No Art. 5, Annex III or Art. 50 trigger declared")

    if tier == "high" and (
        use_case.get("interacts_with_people") or use_case.get("generates_synthetic_content")
    ):
        basis.append("Art. 50 transparency duties also apply")

    score, factors = 0, []
    if domain in ESSENTIAL_DOMAINS or domain in ANNEX_III:
        score += 3
        factors.append("affects access to essential services, livelihood or rights (+3)")
    if use_case.get("decision_role") == "automated_decision":
        score += 2
        factors.append("decisions are automated without human review (+2)")
    if use_case.get("processes_personal_data"):
        score += 1
        factors.append("processes personal data under the DPDP Act (+1)")
    if use_case.get("vulnerable_groups"):
        score += 2
        factors.append("affects vulnerable groups (+2)")
    if int(use_case.get("annual_decisions", 0) or 0) >= 100_000:
        score += 1
        factors.append("operates at large scale (+1)")
    if use_case.get("contestability") == "low":
        score += 1
        factors.append("outcomes are hard to contest or reverse (+1)")
    sensitivity = "high" if score >= 7 else "elevated" if score >= 4 else "low"

    notes = []
    if domain == "credit_scoring" and "IN" in regions:
        notes.append(
            "Regulated lending in India: the RBI FREE-AI framework (Aug 2025) is the sector reference; "
            "the India AI Governance Guidelines' seven sutras are adapted from it."
        )
    if domain == "credit_scoring" and "US" in regions:
        notes.append("US banking organizations: model risk management under SR 26-2 (April 2026).")
    if use_case.get("processes_personal_data") and "IN" in regions:
        notes.append(
            "Personal data of Indian data principals: DPDP Act 2023 and DPDP Rules 2025 apply."
        )

    return Classification(
        eu_tier=tier,
        eu_applicable="EU" in regions or bool(use_case.get("eu_market")),
        eu_basis=basis,
        india_sensitivity=sensitivity,
        india_score=score,
        india_factors=factors,
        sector_notes=notes,
    )


def obligations(
    classification: Classification,
    use_case: dict[str, Any],
    library: ControlLibrary,
    today: date,
) -> list[dict[str, Any]]:
    """Regulatory milestones relevant to this system, with days remaining."""
    regions = {r.upper() for r in use_case.get("deployment_regions", [])}
    tier = classification.eu_tier
    out = []
    for m in library.calendar["milestones"]:
        jurisdiction = m.get("jurisdiction", "EU")
        if jurisdiction == "EU" and not classification.eu_applicable:
            continue
        if jurisdiction not in ("EU",) and jurisdiction not in regions:
            continue
        if m.get("personal_data_only") and not use_case.get("processes_personal_data"):
            continue
        if m.get("sector") == "financial_services" and use_case.get("domain") != "credit_scoring":
            continue
        tiers = set(m.get("tiers", ["all"]))
        if "all" not in tiers and tier not in tiers:
            continue
        due = date.fromisoformat(m["date"])
        out.append(
            {
                "date": m["date"],
                "regime": m["regime"],
                "obligation": m["obligation"],
                "status": "in force" if due <= today else "upcoming",
                "days_remaining": max((due - today).days, 0),
                "source": m["source"],
            }
        )
    return sorted(out, key=lambda o: o["date"])
