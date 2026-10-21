import json

from pramana.audit.engine import run_audit
from pramana.checks.agent_trace import chain_status, event_hash
from pramana.spec import load_spec
from pramana.types import Status


def _chain(events):
    prev = None
    out = []
    for e in events:
        e = dict(e, prev_hash=prev)
        e["hash"] = event_hash(e)
        prev = e["hash"]
        out.append(e)
    return out


BASE = [
    {
        "event_id": "a",
        "ts": "2026-10-01T10:00:00Z",
        "session_id": "s",
        "type": "user_request",
        "actor": "customer:1",
        "parent_id": None,
    },
    {
        "event_id": "b",
        "ts": "2026-10-01T10:00:05Z",
        "session_id": "s",
        "type": "approval",
        "actor": "human:lead",
        "parent_id": "a",
        "decision": "approved",
    },
    {
        "event_id": "c",
        "ts": "2026-10-01T10:00:09Z",
        "session_id": "s",
        "type": "tool_call",
        "actor": "agent:x",
        "parent_id": "a",
        "tool": "issue_refund",
        "approval_id": "b",
        "args": {"amount": 50000},
    },
]


def test_hash_chain_states():
    assert chain_status(BASE) == "absent"
    chained = _chain(BASE)
    assert chain_status(chained) == "valid"
    chained[2]["args"] = {"amount": 99999}
    assert chain_status(chained) == "broken"


def test_example_trace_findings(agent_audit):
    result = next(r for r in agent_audit.results if r.check_id == "agent.trace_auditability")
    assert result.status == Status.FAIL
    assert [u["event_id"] for u in result.details["unapproved"]] == ["e20"]
    assert result.details["unattributed"] == ["e23"]
    assert result.metrics["log_integrity"] == "absent"
    assert result.metrics["approval_coverage"] == 0.5


def _spec(tmp_path, events):
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(e) for e in events))
    spec = tmp_path / "audit.yaml"
    spec.write_text(
        "system: {name: Demo agent, version: '1', type: agent, owner: Ops}\n"
        "use_case: {domain: other, deployment_regions: [IN]}\n"
        "agent:\n  trace: trace.jsonl\n  tool_allowlist: [issue_refund]\n"
        "  high_impact_tools: {issue_refund: {field: amount, above: 10000}}\n"
    )
    return load_spec(spec)


def test_clean_chained_trace_passes(tmp_path):
    result = run_audit(_spec(tmp_path, _chain(BASE)), tmp_path / "pack")
    check = next(r for r in result.results if r.check_id == "agent.trace_auditability")
    assert check.status == Status.PASS
    assert check.metrics["auditability_index"] == 1.0


def test_approval_after_the_action_does_not_count(tmp_path):
    late = [dict(e) for e in BASE]
    late[1]["ts"] = "2026-10-01T10:00:30Z"
    result = run_audit(_spec(tmp_path, _chain(late)), tmp_path / "pack")
    check = next(r for r in result.results if r.check_id == "agent.trace_auditability")
    assert check.status == Status.FAIL
    assert check.metrics["unapproved_high_impact"] == 1


def test_tool_outside_allowlist_fails(tmp_path):
    events = [dict(e) for e in BASE] + [
        {
            "event_id": "d",
            "ts": "2026-10-01T10:00:12Z",
            "session_id": "s",
            "type": "tool_call",
            "actor": "agent:x",
            "parent_id": "a",
            "tool": "delete_account",
            "args": {},
        }
    ]
    result = run_audit(_spec(tmp_path, _chain(events)), tmp_path / "pack")
    check = next(r for r in result.results if r.check_id == "agent.trace_auditability")
    assert check.status == Status.FAIL
    assert check.metrics["allowlist_violations"] == 1
