"""End-to-end checks on the credit-scoring case study.

The case study plants known defects. These tests are the ground truth: each
planted defect must be found, and the clean areas must pass.
"""

import json

import pytest

from pramana.audit.ledger import verify_pack
from pramana.cli import main
from pramana.types import Status

PLANTED = {
    "governance.risk_classification": Status.FAIL,  # owner declared 'limited' for a high-risk use
    "fairness.group_parity": Status.FAIL,  # label bias against rural applicants
    "fairness.intersectional": Status.FAIL,  # gap is wider for sub-groups
    "fairness.proxy_features": Status.FAIL,  # pincode band tracks residence
    "privacy.pii_exposure": Status.FAIL,  # e-mail and mobile left in extracts
    "documentation.model_card": Status.FAIL,  # overstated AUC and missing sections
    "drift.population_stability": Status.WARN,  # income and gig share shifted
    "data_quality.integrity": Status.WARN,  # missing bureau scores and duplicates
    "governance.manual_evidence": Status.WARN,  # FRIA cited but not supplied
}
CLEAN = ["calibration.reliability", "audit.detector_sensitivity", "audit.process"]


def test_planted_defects_are_detected(credit_audit):
    result, _, _ = credit_audit
    by_id = {r.check_id: r for r in result.results}
    for check_id, expected in PLANTED.items():
        assert by_id[check_id].status == expected, (check_id, by_id[check_id].summary)


def test_clean_areas_pass(credit_audit):
    result, _, _ = credit_audit
    by_id = {r.check_id: r for r in result.results}
    for check_id in CLEAN:
        assert by_id[check_id].status == Status.PASS, (check_id, by_id[check_id].summary)


def test_no_check_errors(credit_audit):
    result, _, _ = credit_audit
    assert [r.check_id for r in result.results if r.status == Status.ERROR] == []


def test_specific_evidence(credit_audit):
    result, _, _ = credit_audit
    parity = result.result("fairness.group_parity")
    assert parity.details["attributes"]["residence"]["summary"]["least_favoured"] == "rural"
    proxies = {f["feature"] for f in result.result("fairness.proxy_features").details["flagged"]}
    assert "pincode_risk_band" in proxies
    pii = {h["column"] for h in result.result("privacy.pii_exposure").details["hits"]}
    assert pii == {"contact_email", "mobile"}
    docs = result.result("documentation.model_card").details
    assert any("documented AUC" in m for m in docs["mismatches"])


def test_gate_and_risk_acceptance(credit_audit):
    result, _, _ = credit_audit
    assert result.gate["decision"] == "BLOCK"
    accepted = [r for r in result.risks if r.accepted]
    assert [r.source_check for r in accepted] == ["data_quality.integrity"]
    assert all(r.risk_id not in result.gate["blocking_risks"] for r in accepted)
    scores = [r.score for r in result.risks if not r.accepted]
    assert scores == sorted(scores, reverse=True)


def test_every_result_is_mapped_and_sealed(credit_audit):
    result, _, _ = credit_audit
    for r in result.results:
        if r.check_id != "governance.manual_evidence":
            assert r.controls, r.check_id
        assert r.evidence_hash and len(r.evidence_hash) == 64


def test_pack_outputs_and_verification(credit_audit):
    result, out, paths = credit_audit
    for path in paths.values():
        assert path.exists() and path.stat().st_size > 0
    ok, problems = verify_pack(out)
    assert ok, problems
    html = paths["report"].read_text(encoding="utf-8")
    assert "Release is blocked" in html
    assert result.ledger_root in html
    data = json.loads(paths["results"].read_text(encoding="utf-8"))
    assert data["gate"]["decision"] == "BLOCK"


def test_pack_contains_no_absolute_paths(credit_audit, credit_example):
    _, out, _ = credit_audit
    for file in out.rglob("*"):
        if file.is_file():
            text = file.read_text(encoding="utf-8", errors="ignore")
            assert str(credit_example) not in text, file.name
            assert str(out) not in text, file.name


def test_cli_exit_codes(credit_example, tmp_path, capsys):
    spec = str(credit_example / "audit.yaml")
    out = str(tmp_path / "pack")
    assert main(["run", spec, "--out", out, "--date", "2026-10-21"]) == 1
    assert main(["run", spec, "--out", out, "--no-gate"]) == 0
    assert main(["verify", out]) == 0
    (tmp_path / "pack" / "evidence" / "4-testing" / "fairness.group_parity.json").write_text("{}")
    assert main(["verify", out]) == 2
    assert main(["run", str(tmp_path / "missing.yaml")]) == 3
    assert main(["summary", out]) == 0
    assert "| R-01 |" in capsys.readouterr().out


@pytest.mark.parametrize(
    "command", [["checks"], ["controls", "--framework", "ISO42001"], ["controls", "--markdown"]]
)
def test_informational_commands(command, capsys):
    assert main(command) == 0
    assert capsys.readouterr().out
