"""Convert real-world agent logs into Pramana's event schema.

Production agents do not emit Pramana's native trace format. They emit, most
commonly, one of:

* **OpenTelemetry GenAI spans** — the emerging standard for agent telemetry
  (OTel semantic conventions for ``gen_ai.*``), exported as JSON spans;
* **LangChain / LangGraph run logs** — nested "runs" with a type
  (``chain``/``llm``/``tool``), inputs, outputs and a parent run id.

These adapters map either shape onto Pramana's events so the agent checks can
audit logs a system already produces, instead of requiring instrumentation.
Each adapter is deliberately small, pure and streaming-friendly: it takes an
iterable of raw records and yields Pramana events.

Pramana event schema (one per action):
    {"event_id", "ts", "session_id", "type", "actor", "parent_id", ...}
    type ∈ {user_request, tool_call, tool_result, approval, model_output}

Unknown fields are preserved under the event so no evidence is lost.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

# OpenTelemetry GenAI operation names → Pramana event types.
_OTEL_OP_TYPE = {
    "chat": "model_output",
    "text_completion": "model_output",
    "generate_content": "model_output",
    "execute_tool": "tool_call",
    "invoke_agent": "model_output",
    "create_agent": "model_output",
}

# LangChain run types → Pramana event types.
_LC_RUN_TYPE = {
    "llm": "model_output",
    "chat_model": "model_output",
    "chain": "model_output",
    "tool": "tool_call",
    "retriever": "tool_call",
    "agent": "model_output",
}


def _first(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def from_otel_spans(spans: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Map OpenTelemetry GenAI spans to Pramana events.

    Reads ``attributes`` with ``gen_ai.*`` keys. A span's ``trace_id`` becomes the
    session, ``span_id`` the event id and ``parent_span_id`` the parent. The tool
    name, model and any reasoning/output text are carried across so the
    misalignment and auditability checks have what they need.
    """
    for span in spans:
        attr = span.get("attributes", {}) or {}
        op = _first(attr, "gen_ai.operation.name", "gen_ai.operation", default="")
        etype = _OTEL_OP_TYPE.get(op, "model_output")
        tool = _first(attr, "gen_ai.tool.name", "tool.name")
        if tool and etype == "model_output":
            etype = "tool_call"
        system = _first(attr, "gen_ai.system", "gen_ai.provider.name", default="agent")
        agent_name = _first(attr, "gen_ai.agent.name", default=system)
        event: dict[str, Any] = {
            "event_id": _first(span, "span_id", "spanId", "id"),
            "ts": _first(span, "start_time", "startTime", "timestamp", default=""),
            "session_id": _first(attr, "gen_ai.conversation.id", "session.id")
            or _first(span, "trace_id", "traceId", default=""),
            "type": etype,
            "actor": f"agent:{agent_name}",
            "parent_id": _first(span, "parent_span_id", "parentSpanId") or None,
        }
        if etype == "tool_call" and tool:
            event["tool"] = tool
            args = _first(attr, "gen_ai.tool.call.arguments", "gen_ai.tool.arguments")
            if args is not None:
                event["args"] = args if isinstance(args, dict) else {"input": args}
        model = _first(attr, "gen_ai.request.model", "gen_ai.response.model")
        if model:
            event["model"] = model
        reasoning = _first(attr, "gen_ai.reasoning", "gen_ai.completion.reasoning")
        if reasoning:
            event["reasoning"] = _as_text(reasoning)
        output = _first(
            attr, "gen_ai.output.messages", "gen_ai.completion", "gen_ai.response.content"
        )
        if output is not None:
            event["content"] = _as_text(output)
        yield event


def from_langchain_runs(runs: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Map LangChain/LangGraph run records to Pramana events.

    Each run has an ``id``, a ``run_type`` (or ``type``), ``inputs``/``outputs``,
    a ``parent_run_id`` and timestamps. A root run (no parent) with user input is
    emitted as a ``user_request`` so the auditability check can anchor attribution.
    """
    for run in runs:
        rtype = _first(run, "run_type", "type", default="chain")
        etype = _LC_RUN_TYPE.get(rtype, "model_output")
        parent = _first(run, "parent_run_id", "parent_id", "parentRunId")
        inputs = run.get("inputs") or {}
        outputs = run.get("outputs") or {}
        is_root = not parent

        # A root run carrying human input first surfaces as the originating request.
        if is_root and (inputs or run.get("name")):
            yield {
                "event_id": f"{run.get('id')}:req",
                "ts": _first(run, "start_time", "start", "ts", default=""),
                "session_id": _first(run, "session_id", "thread_id", default="")
                or str(run.get("id")),
                "type": "user_request",
                "actor": "user:caller",
                "parent_id": None,
                "content": _as_text(
                    _first(inputs, "input", "question", "messages", default=inputs)
                ),
            }

        event: dict[str, Any] = {
            "event_id": str(run.get("id")),
            "ts": _first(run, "start_time", "start", "ts", default=""),
            "session_id": _first(run, "session_id", "thread_id", default="")
            or str(_first(run, "parent_run_id", "id", default="")),
            "type": etype,
            "actor": f"agent:{run.get('name', rtype)}",
            "parent_id": (f"{parent}" if parent else (f"{run.get('id')}:req" if is_root else None)),
        }
        if etype == "tool_call":
            event["tool"] = run.get("name", rtype)
            event["args"] = inputs if isinstance(inputs, dict) else {"input": inputs}
        reasoning = _first(outputs, "reasoning", "intermediate_steps", "log")
        if reasoning:
            event["reasoning"] = _as_text(reasoning)
        content = _first(outputs, "output", "text", "content", "messages")
        if content is not None:
            event["content"] = _as_text(content)
        yield event


def _read_records(path: Path) -> list[dict[str, Any]]:
    """Read either a JSON array or JSON Lines file into a list of dicts."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] == "[":
        data = json.loads(text)
        return list(data) if isinstance(data, list) else [data]
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


CONVERTERS = {
    "native": lambda records: iter(records),
    "otel": from_otel_spans,
    "langchain": from_langchain_runs,
}


def load_trace(path: str | Path, fmt: str = "native") -> list[dict[str, Any]]:
    """Load an agent trace in the given format and return Pramana events."""
    if fmt not in CONVERTERS:
        raise ValueError(f"Unknown trace format '{fmt}' (use {', '.join(CONVERTERS)})")
    records = _read_records(Path(path))
    return list(CONVERTERS[fmt](records))


def _iter_raw_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield raw records one at a time. JSON Lines streams; a JSON array is read whole."""
    with path.open(encoding="utf-8") as fh:
        first = fh.read(1)
        while first and first.isspace():
            first = fh.read(1)
        if first == "[":
            rest = first + fh.read()
            data = json.loads(rest)
            yield from (data if isinstance(data, list) else [data])
            return
        # JSON Lines: one object per line, constant memory.
        buffer = first
        for line in fh:
            record = (buffer + line).strip()
            buffer = ""
            if record:
                yield json.loads(record)


def stream_events(path: str | Path, fmt: str = "native") -> Iterator[dict[str, Any]]:
    """Stream Pramana events from a trace without holding the whole file in memory.

    JSON Lines inputs (native and most OTel/LangChain exports) are processed line
    by line, so a multi-gigabyte log scans in constant memory. A JSON *array*
    input is still read whole, because it cannot be parsed incrementally.
    """
    if fmt not in CONVERTERS:
        raise ValueError(f"Unknown trace format '{fmt}' (use {', '.join(CONVERTERS)})")
    converter = CONVERTERS[fmt]
    for record in _iter_raw_records(Path(path)):
        # Feed one raw record at a time; converters are generators over an iterable.
        yield from converter([record])
