from datetime import date

from pramana.controls import load_library
from pramana.risk.classification import classify, obligations


def test_credit_scoring_is_high_risk():
    result = classify(
        {"domain": "credit_scoring", "deployment_regions": ["EU"]}, "tabular_classifier"
    )
    assert result.eu_tier == "high"
    assert result.eu_applicable
    assert any("5(b)" in b for b in result.eu_basis)


def test_fraud_detection_only_is_excluded_from_annex_iii_5b():
    result = classify(
        {"domain": "credit_scoring", "fraud_detection_only": True}, "tabular_classifier"
    )
    assert result.eu_tier == "minimal"


def test_prohibited_flag_wins():
    result = classify(
        {
            "domain": "recruitment",
            "prohibited_practice_flags": ["emotion_recognition_workplace_education"],
        },
        "tabular_classifier",
    )
    assert result.eu_tier == "prohibited"


def test_chatbot_is_limited_risk():
    result = classify(
        {"domain": "customer_support_financial", "interacts_with_people": True}, "llm_application"
    )
    assert result.eu_tier == "limited"


def test_article_6_3_exemption_needs_no_profiling():
    use_case = {"domain": "recruitment", "article_6_3_exemption": True, "performs_profiling": False}
    assert classify(use_case, "tabular_classifier").eu_tier == "minimal"
    use_case["performs_profiling"] = True
    assert classify(use_case, "tabular_classifier").eu_tier == "high"


def test_india_sensitivity_scoring():
    use_case = {
        "domain": "credit_scoring",
        "decision_role": "automated_decision",
        "processes_personal_data": True,
        "annual_decisions": 500_000,
        "deployment_regions": ["IN"],
    }
    result = classify(use_case, "tabular_classifier")
    assert result.india_score == 7
    assert result.india_sensitivity == "high"
    assert any("FREE-AI" in n for n in result.sector_notes)


def test_obligations_respect_jurisdiction_and_tier():
    lib = load_library()
    india_only = {
        "domain": "credit_scoring",
        "deployment_regions": ["IN"],
        "processes_personal_data": True,
    }
    result = classify(india_only, "tabular_classifier")
    regimes = {o["regime"] for o in obligations(result, india_only, lib, date(2026, 10, 21))}
    assert "EU AI Act" not in regimes
    assert "India DPDP Rules 2025" in regimes

    eu = {"domain": "credit_scoring", "deployment_regions": ["EU"]}
    result = classify(eu, "tabular_classifier")
    items = obligations(result, eu, lib, date(2026, 10, 21))
    high_risk = [o for o in items if "Annex III" in o["obligation"]]
    assert high_risk and high_risk[0]["date"] == "2027-12-02"
    assert high_risk[0]["status"] == "upcoming"
