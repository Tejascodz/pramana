"""Regression tests for bugs found reading the 0.4.2 diff line by line, and for hardening."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pramana.adapters.llm import build_client
from pramana.audit.engine import run_audit
from pramana.audit.ledger import EvidenceLedger
from pramana.checks.agent_trace import scan_misalignment
from pramana.checks.llm import numbers_in, unsupported_numbers
from pramana.cli import main
from pramana.metrics import adaptive_calibration_error, single_feature_auc
from pramana.probes import ProbeFileError, load_probe_file
from pramana.reporting import write_outputs
from pramana.spec import ArtifactIntegrityError, SpecError, load_spec
from pramana.types import Status

ROOT = Path(__file__).resolve().parents[1]


def _case(tmp_path, groups, extra_spec="", **cols):
    df = pd.DataFrame({"group": groups, **cols})
    df.to_csv(tmp_path / "eval.csv", index=False)
    (tmp_path / "audit.yaml").write_text(
        "system: {name: Demo, version: '1', type: tabular_classifier, owner: Risk}\n"
        "use_case: {domain: other, deployment_regions: [IN]}\n"
        "artifacts: {evaluation_data: eval.csv}\n"
        "target: label\nscore_column: score\nsensitive_features: [group]\n" + extra_spec,
        encoding="utf-8",
    )
    return load_spec(tmp_path / "audit.yaml")


# Fairness wording -----------------------------------------------------------------


def test_untestable_attribute_never_gets_an_empty_action_list(tmp_path):
    rng = np.random.default_rng(1)
    spec = _case(
        tmp_path, ["A"] * 300 + ["B"] * 10, score=rng.random(310), label=rng.integers(0, 2, 310)
    )
    r = run_audit(spec, tmp_path / "pack").result("fairness.group_parity")
    assert "Attributes needing action: ." not in r.recommendation
    assert "untested, not passed" in r.recommendation


# Self-test ------------------------------------------------------------------------


def test_self_test_skips_the_fairness_canary_when_no_one_is_approved(tmp_path):
    rng = np.random.default_rng(2)
    n = 200
    spec = _case(
        tmp_path,
        ["A"] * 100 + ["B"] * 100,
        score=np.full(n, 0.1),
        label=rng.integers(0, 2, n),
        income=rng.normal(50, 10, n),
    )
    r = run_audit(spec, tmp_path / "pack").result("audit.detector_sensitivity")
    assert not any(c["canary"].startswith("halve") for c in r.details["canaries"])
    assert r.status != Status.FAIL


# Groundedness in both directions --------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "kb"),
    [
        ("You can borrow up to Rs 5 lakh.", "Loans up to Rs 5,00,000."),
        ("Up to 1.5 crore.", "Up to 1,50,00,000."),
        ("2.5 million users", "We serve 25,00,000 users"),
    ],
)
def test_magnitude_words_match_digits_in_either_direction(answer, kb):
    assert unsupported_numbers(answer, kb, "") == []


def test_a_word_starting_with_cr_is_not_a_crore():
    assert numbers_in("You have 5 credit cards.") == {"5"}
    assert unsupported_numbers("You have 5 credit cards.", "Customers may hold 5 cards.", "") == []


# Sentence boundaries ----------------------------------------------------------------


def test_no_and_ms_end_sentences():
    # "no." ends the first sentence, so the second sentence's first person does not reach back.
    text = "The reviewer asked whether to hide the error report from the user, and the answer was no. I will continue the task."
    ev = {"event_id": "x", "session_id": "s", "type": "model_output", "reasoning": text}
    assert not any(s["pattern"] == "deception" for s in scan_misalignment([ev]))


# Signing key from a one-line secret -------------------------------------------------


def test_sign_accepts_a_pem_stored_with_literal_newlines(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    from pramana.audit.signing import generate_keypair

    spec = load_spec(ROOT / "examples" / "agent_traces" / "audit.yaml")
    result = run_audit(spec, tmp_path / "pack")
    write_outputs(result, tmp_path / "pack", ledger=result.ledger)
    private, _ = generate_keypair()
    monkeypatch.setenv("PRAMANA_SIGNING_KEY_PEM", private.decode().replace("\n", "\\n"))
    assert main(["sign", str(tmp_path / "pack")]) == 0


# Benchmark converter usage ------------------------------------------------------------


def test_converter_prints_usage_instead_of_crashing():
    script = ROOT / "examples" / "benchmark_whowhen" / "convert_whowhen.py"
    out = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "usage" in out.stdout


# Artifact hash pinning ------------------------------------------------------------------


def _pinned(tmp_path, digest):
    rng = np.random.default_rng(3)
    return _case(
        tmp_path,
        ["A"] * 60 + ["B"] * 60,
        extra_spec=f"artifacts_sha256: {{evaluation_data: '{digest}'}}\n",
        score=rng.random(120),
        label=rng.integers(0, 2, 120),
    )


def test_a_matching_pin_lets_the_audit_run(tmp_path):
    _pinned(tmp_path, "0" * 64)  # writes eval.csv
    digest = hashlib.sha256((tmp_path / "eval.csv").read_bytes()).hexdigest()
    spec = _pinned(tmp_path, digest)
    assert run_audit(spec, tmp_path / "pack").results


def test_a_changed_artifact_is_refused_before_anything_runs(tmp_path):
    spec = _pinned(tmp_path, "0" * 64)
    with pytest.raises(ArtifactIntegrityError):
        run_audit(spec, tmp_path / "pack")
    assert main(["run", str(tmp_path / "audit.yaml"), "--out", str(tmp_path / "p2")]) == 3


@pytest.mark.parametrize(
    "pins", ["{evaluation_data: 'abc'}", "{modell: '" + "0" * 64 + "'}", "'not a mapping'"]
)
def test_malformed_pins_are_spec_errors(tmp_path, pins):
    (tmp_path / "eval.csv").write_text("group,score,label\nA,0.5,1\n", encoding="utf-8")
    (tmp_path / "audit.yaml").write_text(
        "system: {name: D, version: '1', type: tabular_classifier, owner: R}\n"
        "use_case: {domain: other}\nartifacts: {evaluation_data: eval.csv}\n"
        f"target: label\nscore_column: score\nartifacts_sha256: {pins}\n",
        encoding="utf-8",
    )
    with pytest.raises(SpecError):
        load_spec(tmp_path / "audit.yaml")


# Ledger, probes and endpoint config ------------------------------------------------------


def test_the_ledger_refuses_to_write_outside_the_pack(tmp_path):
    ledger = EvidenceLedger(tmp_path / "pack")
    with pytest.raises(ValueError, match="outside the audit pack"):
        ledger.add_text("4-testing", "escape", "../escape.txt", "x")
    assert not (tmp_path / "escape.txt").exists()


def test_a_missing_probe_include_is_a_clear_error(tmp_path):
    probes = tmp_path / "probes.yaml"
    probes.write_text("include: [missing.yaml]\n", encoding="utf-8")
    with pytest.raises(ProbeFileError, match="not found"):
        load_probe_file(probes)


def test_http_mode_refuses_get_because_the_prompt_is_in_the_body():
    cfg = {"mode": "http", "url": "http://127.0.0.1:9/x", "body": {"q": "{prompt}"},
           "response_path": "a", "method": "GET"}  # fmt: skip
    with pytest.raises(ValueError, match="POST, PUT or PATCH"):
        build_client(cfg)


# Statistics -------------------------------------------------------------------------------


def test_a_unique_id_column_is_not_reported_as_a_strong_signal():
    rng = np.random.default_rng(99)
    ids = pd.Series([f"ID-{i:05d}" for i in range(500)])
    assert single_feature_auc(ids, pd.Series(rng.integers(0, 2, 500))) < 0.6
    g = pd.Series(rng.choice(["urban", "rural"], 2000))
    y = pd.Series(((g == "urban") ^ (rng.random(2000) < 0.1)).astype(int))
    assert single_feature_auc(g, y) > 0.8  # a real association is kept


def test_adaptive_ece_sees_miscalibration_that_equal_width_bins_blur():
    p = np.r_[np.full(900, 0.02), np.full(100, 0.98)]
    y = np.r_[np.zeros(900), np.ones(50), np.zeros(50)]
    assert adaptive_calibration_error(y, p) > 0.04


def test_credit_audit_reports_tail_privacy_and_base_rates(tmp_path):
    spec = load_spec(ROOT / "examples" / "credit_scoring" / "audit.yaml")
    r = run_audit(spec, tmp_path / "pack")
    mia = r.result("privacy.membership_inference")
    assert mia.metrics["tpr_at_1pct_fpr"] is not None
    parity = r.result("fairness.group_parity")
    rows = next(iter(parity.details["attributes"].values()))["groups"]
    assert all("base_rate" in row for row in rows)


# ML-BOM ---------------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["credit_scoring", "support_chatbot", "agent_traces"])
def test_ml_bom_is_valid_cyclonedx_1_7(tmp_path, case):
    spec = load_spec(ROOT / "examples" / case / "audit.yaml")
    result = run_audit(spec, tmp_path / "pack")
    paths = write_outputs(result, tmp_path / "pack", ledger=result.ledger)
    bom = json.loads(paths["ml_bom"].read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.7"
    assert bom["serialNumber"].startswith("urn:uuid:")
    hashes = {h["content"] for c in bom["components"] for h in c["hashes"]}
    assert hashes <= {a["sha256"] for a in result.artifacts}
    validation = pytest.importorskip("cyclonedx.validation.json")
    schema = pytest.importorskip("cyclonedx.schema")
    errors = validation.JsonStrictValidator(schema.SchemaVersion.V1_7).validate_str(
        json.dumps(bom), all_errors=True
    )
    assert not errors, list(errors)[:3]


def test_ml_bom_is_sealed_in_the_ledger(tmp_path):
    spec = load_spec(ROOT / "examples" / "agent_traces" / "audit.yaml")
    result = run_audit(spec, tmp_path / "pack")
    write_outputs(result, tmp_path / "pack", ledger=result.ledger)
    bom = tmp_path / "pack" / "ml_bom.cdx.json"
    bom.write_text(bom.read_text().replace("CycloneDX", "Edited"), encoding="utf-8")
    assert main(["verify", str(tmp_path / "pack")]) != 0


def test_examples_still_verify_after_copy(tmp_path):
    src = ROOT / "docs" / "sample-audits" / "credit_scoring"
    shutil.copytree(src, tmp_path / "copy")
    assert main(["verify", str(tmp_path / "copy")]) == 0
