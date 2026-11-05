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


# Awkward but realistic data: found by feeding edge cases to the tabular checks.


def _tabular(tmp_path: Path, mutate) -> Path:
    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(1)
    df = pd.DataFrame({"x1": rng.normal(size=400), "group": rng.choice(["A", "B"], size=400)})
    df["y"] = (df.x1 + rng.normal(scale=0.5, size=400) > 0).astype(int)
    df["s"] = 1 / (1 + np.exp(-2 * df.x1))
    mutate(df, rng).to_csv(tmp_path / "eval.csv", index=False)
    spec = tmp_path / "audit.yaml"
    spec.write_text(
        "system: {name: M, version: '1', type: tabular_classifier, owner: O}\n"
        "use_case: {domain: credit_scoring}\n"
        "artifacts: {evaluation_data: eval.csv}\ntarget: y\nscore_column: s\n"
        "sensitive_features: [group]\nfeatures: [x1]\n",
        encoding="utf-8",
    )
    return spec


def test_one_outcome_class_is_not_a_performance_pass(tmp_path):
    spec = _tabular(tmp_path, lambda d, rng: d.assign(y=1))
    check = run_audit(load_spec(spec), tmp_path / "p").result("performance.discrimination")
    assert check.status == Status.ERROR and "only one outcome class" in check.summary


def test_missing_scores_are_named_not_a_raw_nan_error(tmp_path):
    import numpy as np

    spec = _tabular(
        tmp_path, lambda d, rng: d.assign(s=np.where(rng.random(len(d)) < 0.3, np.nan, d.s))
    )
    check = run_audit(load_spec(spec), tmp_path / "p").result("fairness.group_parity")
    assert check.status == Status.ERROR and "score_column 's' has" in check.summary


def test_missing_labels_are_not_counted_as_negative_outcomes(tmp_path):
    import numpy as np

    spec = _tabular(
        tmp_path, lambda d, rng: d.assign(y=np.where(rng.random(len(d)) < 0.1, np.nan, d.y))
    )
    check = run_audit(load_spec(spec), tmp_path / "p").result("performance.discrimination")
    assert check.status == Status.ERROR and "missing label" in check.summary


def test_a_missing_protected_attribute_is_its_own_group(tmp_path):
    import numpy as np

    spec = _tabular(
        tmp_path, lambda d, rng: d.assign(group=np.where(rng.random(len(d)) < 0.2, None, d.group))
    )
    check = run_audit(load_spec(spec), tmp_path / "p").result("fairness.group_parity")
    assert check.status != Status.ERROR, check.summary
    groups = [row["group"] for a in check.details["attributes"].values() for row in a["groups"]]
    assert "(missing)" in groups


# Messy agent logs.


def _agent(tmp_path: Path, trace: str) -> Path:
    (tmp_path / "t.jsonl").write_text(trace, encoding="utf-8")
    spec = tmp_path / "audit.yaml"
    spec.write_text(
        "system: {name: A, version: '1', type: agent, owner: O}\n"
        "use_case: {domain: customer_support_financial}\n"
        "agent: {trace: t.jsonl, tool_allowlist: [issue_refund],"
        " high_impact_tools: {issue_refund: {field: amount, above: 10000}}}\n",
        encoding="utf-8",
    )
    return spec


def test_an_empty_agent_log_blocks_instead_of_passing(tmp_path):
    result = run_audit(load_spec(_agent(tmp_path, "")), tmp_path / "p")
    assert "contains no events" in result.result("agent.trace_auditability").summary
    assert result.gate["decision"] == "BLOCK"


def test_a_corrupt_log_line_is_named(tmp_path):
    good = '{"event_id":"e1","ts":"2026-10-14T09:00:00+05:30","session_id":"s","type":"user_request","actor":"c:x"}'
    result = run_audit(load_spec(_agent(tmp_path, good + "\n{not json\n")), tmp_path / "p")
    assert "line 2 is not valid JSON" in result.result("agent.trace_auditability").summary


def test_an_event_without_an_id_is_scored_not_a_crash(tmp_path):
    trace = '{"type":"tool_call","tool":"issue_refund","args":{"amount":50000}}\n'
    check = run_audit(load_spec(_agent(tmp_path, trace)), tmp_path / "p").result(
        "agent.trace_auditability"
    )
    assert check.status == Status.FAIL, check.summary


# A broken endpoint that answers HTTP 200 with an empty string to everything.


def test_an_endpoint_that_returns_empty_answers_cannot_pass(tmp_path):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Empty(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = json.dumps(
                {"model": "m", "choices": [{"message": {"role": "assistant", "content": ""}}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Empty)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        chatbot = ROOT / "examples" / "support_chatbot"
        spec = tmp_path / "audit.yaml"
        spec.write_text(
            "system: {name: Bot, version: '1', type: llm_application, owner: O}\n"
            "use_case: {domain: customer_support_financial, interacts_with_people: true}\n"
            f"llm: {{mode: openai_compatible, base_url: 'http://127.0.0.1:{server.server_address[1]}/v1',"
            f" model: m, probes: '{chatbot / 'probes.yaml'}'}}\n"
            "checks: {exclude: [llm.policy_adherence, llm.groundedness]}\n",
            encoding="utf-8",
        )
        result = run_audit(load_spec(spec), tmp_path / "p")
    finally:
        server.shutdown()
        server.server_close()
    for check_id in ("llm.prompt_injection", "llm.sensitive_disclosure"):
        assert result.result(check_id).status != Status.PASS, check_id
    health = result.result("llm.service_health")
    assert health.status == Status.FAIL and "empty answer" in health.summary
    assert result.gate["decision"] == "BLOCK"
