"""Regression tests: audit decisions and report wording match what actually happened.

Before 0.8.0 a workflow that starts with an approval step was flagged as unguarded, an
evaluation with no judged answer could pass, and the report said incomplete checks block
the release even when ``gate.allow_incomplete`` let it pass.
"""

from __future__ import annotations

import copy

import pytest

from pramana.adapters.llm import Completion
from pramana.checks.agent_sandbox import unguarded_paths
from pramana.checks.llm import _evaluate
from pramana.reporting import render_html
from pramana.types import Status

SUCC = {"approval": {"refund"}, "start": {"refund"}}


def test_a_workflow_that_starts_with_approval_is_guarded():
    assert unguarded_paths("approval", SUCC, {"refund"}, {"approval"}) == []


def test_control_a_workflow_without_approval_is_still_flagged():
    assert unguarded_paths("start", SUCC, {"refund"}, {"approval"}) == [["start", "refund"]]


def test_control_an_approval_on_the_way_still_guards():
    succ = {"start": {"approval"}, "approval": {"refund"}}
    assert unguarded_paths("start", succ, {"refund"}, {"approval"}) == []


def test_an_evaluation_with_nothing_judged_is_an_error_not_a_pass():
    probe = {"id": "P1", "prompt": "x"}
    with pytest.raises(RuntimeError, match="could be judged"):
        _evaluate([probe], [[]], lambda p, c: (False, {}))


def test_control_a_judged_answer_is_evaluated():
    probe = {"id": "P1", "prompt": "x"}
    rows, totals = _evaluate([probe], [[Completion(text="no")]], lambda p, c: (False, {}))
    assert totals["evaluated_samples"] == 1 and not rows[0]["failed"]


def _with_incomplete(result, allow: bool):
    changed = copy.copy(result)
    changed.spec = copy.copy(result.spec)
    changed.spec.gate = {"allow_incomplete": allow}
    changed.gate = {
        **result.gate,
        "incomplete_checks": ["llm.groundedness"],
        "decision": "PASS" if allow else "BLOCK",
        "blocking_risks": [],
    }
    return changed


def test_the_report_does_not_claim_a_block_when_allow_incomplete_lets_it_pass(chatbot_audit):
    html = render_html(_with_incomplete(chatbot_audit, allow=True))
    assert "blocks until they are re-run" not in html
    assert "allow_incomplete" in html


def test_control_the_report_says_incomplete_checks_block_when_they_do(chatbot_audit):
    html = render_html(_with_incomplete(chatbot_audit, allow=False))
    assert "blocks until they are re-run" in html


def test_checks_run_counts_the_checks_the_gate_weighed(chatbot_audit):
    weighed = [
        r
        for r in chatbot_audit.results
        if r.status != Status.SKIPPED and r.check_id != "audit.process"
    ]
    assert chatbot_audit.gate["checks_run"] == len(weighed)
    assert chatbot_audit.results[-1].check_id == "audit.process"
