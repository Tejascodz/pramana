from pramana.checks.llm import find_pii, numbers_in, unsupported_numbers
from pramana.types import Status


def test_number_normalisation_handles_indian_formats():
    assert "1000000" in numbers_in("up to ₹10,00,000")
    assert "11.5%" in numbers_in("rates from 11.5% p.a.")
    assert "1999" in numbers_in("minimum Rs. 1,999")


def test_unsupported_numbers_flags_invented_figures():
    kb = "Foreclosure charge is 3% of the outstanding principal."
    assert unsupported_numbers("The charge is 3% of principal.", kb, "") == []
    assert unsupported_numbers("The charge is 4% plus ₹500.", kb, "") == ["4%", "500"]


def test_numbers_from_the_prompt_are_not_hallucinations():
    assert unsupported_numbers("Your loan NF-2231 is active.", "", "status of loan NF-2231?") == []


def test_find_pii():
    assert set(find_pii("mail priya.r@example.in or call 9876501234")) == {"email", "india_mobile"}
    assert find_pii("No personal data here.") == []


def test_chatbot_audit_finds_exactly_the_planted_failures(chatbot_audit):
    by_id = {r.check_id: r for r in chatbot_audit.results}

    injection = by_id["llm.prompt_injection"]
    assert injection.status == Status.FAIL
    assert [p["probe_id"] for p in injection.details["probes"] if p["succeeded"]] == ["PI-03"]
    assert injection.metrics["canary_leaked"] is False

    disclosure = by_id["llm.sensitive_disclosure"]
    assert [p["probe_id"] for p in disclosure.details["probes"] if p["disclosed"]] == ["SD-02"]

    grounded = by_id["llm.groundedness"]
    assert [p["probe_id"] for p in grounded.details["probes"] if not p["grounded"]] == ["GR-04"]

    policy = by_id["llm.policy_adherence"]
    assert [p["probe_id"] for p in policy.details["probes"] if not p["compliant"]] == ["PO-02"]

    assert by_id["documentation.model_card"].status == Status.PASS
    assert chatbot_audit.gate["decision"] == "BLOCK"


def test_transcript_is_kept_as_evidence(chatbot_audit):
    assert len(chatbot_audit.llm_transcript) == 18
    assert {t["category"] for t in chatbot_audit.llm_transcript} == {
        "prompt_injection",
        "sensitive_disclosure",
        "groundedness",
        "policy",
    }
