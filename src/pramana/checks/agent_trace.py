"""Auditability of AI-agent action logs.

Agents act on their own, so the audit question is whether each action can be
traced to an authorising request, whether high-impact actions had prior human
approval, whether only permitted tools were used, and whether the log is
tamper-evident. Expected event format (one JSON object per line):

    {"event_id": "e1", "ts": "...", "session_id": "s1", "type": "user_request",
     "actor": "customer:C-1", "parent_id": null, ...}

Event types: user_request, tool_call, tool_result, approval, model_output.
Optional "hash"/"prev_hash" fields make the log a hash chain.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pramana.context import AuditContext
from pramana.registry import register
from pramana.types import CheckResult, Severity, Status

REQUIRED_FIELDS = ("event_id", "ts", "session_id", "type", "actor")
ROOT_TYPES = {"user_request", "scheduled_trigger"}


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def event_hash(event: dict[str, Any]) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def chain_status(events: list[dict[str, Any]]) -> str:
    if not any("hash" in e for e in events):
        return "absent"
    prev = None
    for e in events:
        if e.get("prev_hash") != prev or e.get("hash") != event_hash(e):
            return "broken"
        prev = e["hash"]
    return "valid"


def _is_high_impact(call: dict[str, Any], rules: dict[str, Any]) -> bool:
    rule = rules.get(call.get("tool"))
    if rule is None:
        return False
    if rule is True:
        return True
    field, limit = rule.get("field"), rule.get("above")
    try:
        return float(call.get("args", {}).get(field, 0)) > float(limit)
    except (TypeError, ValueError):
        return True


@register(
    "agent.trace_auditability",
    title="Agent action auditability",
    category="Accountability",
    system_types=("agent",),
    order=20,
)
def trace_auditability(ctx: AuditContext) -> CheckResult:
    events = ctx.agent_events
    cfg = ctx.spec.agent
    allowlist = set(cfg.get("tool_allowlist", []))
    high_impact = cfg.get("high_impact_tools", {})
    minimum = ctx.spec.threshold("agent_auditability_min")
    by_id = {e.get("event_id"): e for e in events}

    complete = [all(e.get(f) not in (None, "") for f in REQUIRED_FIELDS) for e in events]
    schema_score = sum(complete) / len(events) if events else 0.0

    calls = [e for e in events if e.get("type") == "tool_call"]

    def root_of(event: dict[str, Any]) -> dict[str, Any] | None:
        seen = set()
        node = event
        while node and node.get("parent_id") and node.get("event_id") not in seen:
            seen.add(node.get("event_id"))
            node = by_id.get(node["parent_id"])
        return node if node and node.get("type") in ROOT_TYPES else None

    unattributed = [c["event_id"] for c in calls if root_of(c) is None]
    attribution = 1 - len(unattributed) / len(calls) if calls else 1.0

    unapproved = []
    high_calls = [c for c in calls if _is_high_impact(c, high_impact)]
    for call in high_calls:
        approval = by_id.get(call.get("approval_id"))
        ok = (
            approval is not None
            and approval.get("type") == "approval"
            and str(approval.get("actor", "")).startswith("human:")
            and approval.get("decision", "approved") == "approved"
            and _ts(approval["ts"]) <= _ts(call["ts"])
        )
        if not ok:
            unapproved.append(
                {
                    "event_id": call["event_id"],
                    "tool": call.get("tool"),
                    "args": call.get("args", {}),
                }
            )
    approval_score = 1 - len(unapproved) / len(high_calls) if high_calls else 1.0

    off_list = [
        {"event_id": c["event_id"], "tool": c.get("tool")}
        for c in calls
        if allowlist and c.get("tool") not in allowlist
    ]

    order_errors = 0
    for e in events:
        parent = by_id.get(e.get("parent_id"))
        if parent and "ts" in parent and "ts" in e and _ts(parent["ts"]) > _ts(e["ts"]):
            order_errors += 1
    temporal_score = 1 - order_errors / len(events) if events else 0.0

    integrity = chain_status(events)
    integrity_score = {"valid": 1.0, "absent": 0.5, "broken": 0.0}[integrity]

    index = (schema_score + attribution + approval_score + temporal_score + integrity_score) / 5

    if unapproved or off_list or integrity == "broken":
        status, severity = Status.FAIL, Severity.CRITICAL if unapproved else Severity.HIGH
    elif index < minimum or integrity == "absent":
        status, severity = Status.WARN, Severity.MEDIUM
    else:
        status, severity = Status.PASS, Severity.INFO

    problems = []
    if unapproved:
        problems.append(
            f"{len(unapproved)} high-impact action(s) without valid prior human approval ("
            + ", ".join(f"{u['event_id']} {u['tool']}" for u in unapproved)
            + ")"
        )
    if unattributed:
        problems.append(
            f"{len(unattributed)} tool call(s) not traceable to a request ({', '.join(unattributed)})"
        )
    if off_list:
        problems.append(
            f"{len(off_list)} call(s) to tools outside the allowlist ({', '.join(o['tool'] for o in off_list)})"
        )
    if integrity != "valid":
        problems.append(f"hash chain {integrity}, so the log is not tamper-evident")

    return CheckResult(
        check_id="agent.trace_auditability",
        title="Agent action auditability",
        category="Accountability",
        status=status,
        severity=severity,
        summary=(
            f"Auditability index {index:.2f} (minimum {minimum}) over {len(events)} events and {len(calls)} "
            f"tool calls: schema {schema_score:.0%}, attribution {attribution:.0%}, approvals "
            f"{approval_score:.0%}, ordering {temporal_score:.0%}, integrity {integrity}. "
            + ("; ".join(problems) + "." if problems else "")
        ),
        plain_summary=(
            "The agent took a high-impact action (such as issuing money) without a recorded human approval, "
            "and parts of its log cannot prove what happened."
            if unapproved
            else "Some agent actions cannot be traced back to who asked for them."
            if status != Status.PASS
            else "Every agent action can be traced to a request and, where required, a human approval."
        ),
        recommendation=(
            "Enforce approval in the tool gateway (not in the prompt), require a parent request for every "
            "tool call, restrict tools to an allowlist, and write logs to an append-only hash chain."
        ),
        metrics={
            "auditability_index": round(index, 4),
            "attribution_rate": round(attribution, 4),
            "approval_coverage": round(approval_score, 4),
            "unapproved_high_impact": len(unapproved),
            "allowlist_violations": len(off_list),
            "log_integrity": integrity,
        },
        details={"unapproved": unapproved, "unattributed": unattributed, "off_allowlist": off_list},
    )
