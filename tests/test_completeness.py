"""The gate never passes a system whose tests could not run.

Found in the 0.7.8 file-by-file review: with every data file of the credit case study
missing and the risk tier declared correctly, all thirteen model checks were skipped
and the gate said PASS.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pramana.audit.engine import run_audit
from pramana.spec import SpecError, load_spec
from pramana.types import Status

ROOT = Path(__file__).resolve().parents[1]
CREDIT = ROOT / "examples" / "credit_scoring"


def _credit_copy(
    tmp_path: Path, *, with_data: Path | None = None, drop: tuple[str, ...] = ()
) -> Path:
    target = tmp_path / "credit"
    shutil.copytree(
        CREDIT, target, ignore=shutil.ignore_patterns("data", "model.joblib", "__pycache__")
    )
    if with_data is not None:
        shutil.copytree(with_data / "data", target / "data")
        shutil.copy(with_data / "model.joblib", target / "model.joblib")
    spec = target / "audit.yaml"
    text = spec.read_text(encoding="utf-8").replace(
        "declared_eu_tier: limited", "declared_eu_tier: high"
    )
    for line in drop:
        text = "\n".join(x for x in text.splitlines() if line not in x) + "\n"
    spec.write_text(text, encoding="utf-8")
    return spec


def test_declared_but_missing_inputs_block_the_gate(tmp_path):
    result = run_audit(load_spec(_credit_copy(tmp_path)), tmp_path / "pack")
    fairness = result.result("fairness.group_parity")
    assert fairness.status == Status.ERROR
    assert "declared in the spec but not found" in fairness.summary
    assert result.gate["decision"] == "BLOCK"
    assert "fairness.group_parity" in result.gate["incomplete_checks"]
    assert result.opinion["rating"] == "Incomplete"


def test_an_input_that_was_never_declared_is_only_not_applicable(tmp_path, credit_example):
    spec = _credit_copy(tmp_path, with_data=credit_example, drop=("documentation:",))
    result = run_audit(load_spec(spec), tmp_path / "pack")
    assert result.result("documentation.model_card").status == Status.SKIPPED
    assert "documentation.model_card" not in result.gate["incomplete_checks"]


def test_a_declared_agent_trace_that_is_missing_is_an_error_with_a_clear_message(tmp_path):
    spec = tmp_path / "audit.yaml"
    spec.write_text(
        "system: {name: A, version: '1', type: agent, owner: O}\n"
        "use_case: {domain: customer_support_financial}\n"
        "agent: {trace: trace.jsonl}\n",
        encoding="utf-8",
    )
    result = run_audit(load_spec(spec), tmp_path / "pack")
    check = result.result("agent.trace_auditability")
    assert check.status == Status.ERROR
    assert "agent.trace is declared in the spec but not found" in check.summary
    assert "FileNotFoundError" not in check.summary
    assert result.gate["decision"] == "BLOCK"


def test_the_gate_blocks_when_no_technical_test_ran(tmp_path, credit_example):
    spec_path = _credit_copy(tmp_path, with_data=credit_example)
    spec = load_spec(spec_path)
    spec.checks = {"include": ["governance.risk_classification"]}
    result = run_audit(spec, tmp_path / "pack")
    assert "no technical test ran" in result.gate["incomplete_checks"]
    assert result.gate["decision"] == "BLOCK"


def test_diff_counts_a_dropped_check_against_fail_on_regression(tmp_path, capsys):
    """Excluding a failing test from the next audit must not pass a regression gate."""
    import json

    from pramana.cli import main

    old = ROOT / "docs" / "sample-audits" / "support_chatbot"
    new = tmp_path / "new"
    new.mkdir()
    results = json.loads((old / "results.json").read_text(encoding="utf-8"))
    dropped = next(r for r in results["results"] if r["status"] == "fail")
    results["results"] = [r for r in results["results"] if r is not dropped]
    (new / "results.json").write_text(json.dumps(results), encoding="utf-8")
    assert main(["diff", str(old), str(new)]) == 0
    assert main(["diff", str(old), str(new), "--fail-on-regression"]) == 1
    out = capsys.readouterr().out
    assert f"`{dropped['check_id']}` | fail | - | **removed**" in out
    assert "1 removed after running in the earlier audit" in out


def _spec_with_acceptance(tmp_path: Path, acceptance: str) -> Path:
    spec = tmp_path / "audit.yaml"
    spec.write_text(
        "system: {name: A, version: '1', type: agent, owner: O}\n"
        "use_case: {domain: customer_support_financial}\n"
        f"agent: {{trace: {ROOT / 'examples/agent_traces/refund_agent_trace.jsonl'}}}\n"
        f"governance:\n  risk_acceptances:\n    - {acceptance}\n",
        encoding="utf-8",
    )
    return spec


@pytest.mark.parametrize(
    "acceptance, problem",
    [
        ("{check: agent.trace_auditability, approved_by: CRO, justification: ok}", "expires"),
        (
            "{check: agent.trace_auditability, approved_by: CRO, justification: ok, expires: soon}",
            "date",
        ),
        (
            "{check: agent.trace_audit, approved_by: CRO, justification: ok, expires: '2027-01-01'}",
            "not a Pramana check",
        ),
        (
            "{check: agent.trace_auditability, justification: ok, expires: '2027-01-01'}",
            "approved_by",
        ),
    ],
)
def test_malformed_risk_acceptances_are_refused(tmp_path, acceptance, problem):
    with pytest.raises(SpecError, match=problem):
        load_spec(_spec_with_acceptance(tmp_path, acceptance))


def test_an_acceptance_stops_blocking_only_until_it_expires(tmp_path):
    from datetime import date

    acc = "{check: agent.trace_auditability, approved_by: CRO, justification: ok, expires: '2027-01-01'}"
    spec = load_spec(_spec_with_acceptance(tmp_path, acc))
    before = run_audit(spec, tmp_path / "a", audit_date=date(2026, 12, 31))
    after = run_audit(spec, tmp_path / "b", audit_date=date(2027, 1, 2))
    risk = lambda r: next(x for x in r.risks if x.source_check == "agent.trace_auditability")  # noqa: E731
    assert risk(before).accepted and not risk(after).accepted
