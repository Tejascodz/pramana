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
from datetime import datetime, timezone
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


def _otel_time(span: dict[str, Any]) -> str:
    """The span's start as ISO 8601. OTLP JSON gives nanoseconds since the epoch."""
    value = _first(span, "start_time", "startTime", "timestamp")
    if value is not None:
        return str(value)
    nanos = _first(span, "startTimeUnixNano", "start_time_unix_nano")
    try:
        return datetime.fromtimestamp(int(nanos) / 1e9, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _otel_args(value: Any) -> dict[str, Any]:
    """Tool arguments as a dict. The GenAI conventions record them as a JSON string."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"input": value}
        return parsed if isinstance(parsed, dict) else {"input": parsed}
    return value if isinstance(value, dict) else {"input": value}


def _documents(value: Any) -> list[dict[str, Any]] | None:
    """Retrieved documents as ``{"content", "source"}``: LangChain ``Document`` dicts or text."""
    if not isinstance(value, list):
        return None
    docs = []
    for item in value:
        if isinstance(item, dict):
            meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            text = _first(item, "page_content", "content", "text", default="")
            docs.append(
                {"content": _as_text(text), "source": meta.get("source") or meta.get("url")}
            )
        else:
            docs.append({"content": _as_text(item), "source": None})
    return docs


def _result_text(result: Any) -> str:
    docs = _documents(result)
    if docs is not None:
        return "\n".join((f"[{d['source']}] " if d["source"] else "") + d["content"] for d in docs)
    return _as_text(result)


def _tool_result(call: dict[str, Any], result: Any, ts: str) -> dict[str, Any]:
    """What a tool or retriever returned, as data the agent read (screened for injection)."""
    return {
        "event_id": f"{call['event_id']}:result",
        "ts": ts or call.get("ts", ""),
        "session_id": call.get("session_id", ""),
        "type": "tool_result",
        "actor": f"tool:{call.get('tool', 'unknown')}",
        "parent_id": call["event_id"],
        "tool": call.get("tool"),
        "result": docs if (docs := _documents(result)) is not None else result,
        "content": _result_text(result),
    }


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
            "ts": _otel_time(span),
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
                event["args"] = _otel_args(args)
        model = _first(attr, "gen_ai.request.model", "gen_ai.response.model")
        if model:
            event["model"] = model
        reasoning = _first(attr, "gen_ai.reasoning", "gen_ai.completion.reasoning")
        if reasoning:
            event["reasoning"] = _as_text(reasoning)
        prompt = _first(attr, "gen_ai.input.messages", "gen_ai.prompt")
        if prompt is not None:
            event["input"] = _as_text(prompt)
        if etype == "tool_call":
            yield event
            result = _first(attr, "gen_ai.tool.call.result", "gen_ai.tool.result")
            if result is not None:
                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except json.JSONDecodeError:
                        pass
                yield _tool_result(event, result, _first(span, "end_time", "endTime", default=""))
            continue
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
            yield event
            # What the tool or retriever returned is data the agent read, not its own words:
            # it becomes a tool_result (screened for planted instructions), never the call's
            # content (which the misalignment scan would read as the agent's reasoning).
            result = (
                _first(outputs, "documents", "output", "result", "text", "content")
                if isinstance(outputs, dict)
                else outputs
            )
            if result is not None and result != {}:
                yield _tool_result(event, result, _first(run, "end_time", "end", default=""))
            continue
        # The prompt, messages or retrieved context the model was given: kept as evidence and
        # screened for planted instructions, but never read as the model's own reasoning.
        prompt = (
            _first(inputs, "prompt", "prompts", "messages", "input")
            if isinstance(inputs, dict)
            else inputs
        )
        if prompt and rtype in ("llm", "chat_model"):  # a chain's input is the user's own message
            event["input"] = _as_text(prompt)
        reasoning = _first(outputs, "reasoning", "intermediate_steps", "log")
        if reasoning:
            event["reasoning"] = _as_text(reasoning)
        content = _first(outputs, "output", "text", "content", "messages", "generations")
        if content is not None:
            event["content"] = _as_text(content)
        yield event


def _object(record: Any, where: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError(f"{where} is not a JSON object (got {type(record).__name__})")
    return record


def _read_records(path: Path) -> list[dict[str, Any]]:
    """Read either a JSON array or JSON Lines file into a list of dicts."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] == "[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path.name} is not valid JSON ({exc.msg}, line {exc.lineno})"
            ) from exc
        data = data if isinstance(data, list) else [data]
        return [_object(r, f"{path.name} item {i}") for i, r in enumerate(data, 1)]
    records = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line:
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path.name} line {line_no} is not valid JSON ({exc.msg}); fix or remove it"
                ) from exc
            records.append(_object(record, f"{path.name} line {line_no}"))
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
        skipped_lines = 0
        first = fh.read(1)
        while first and first.isspace():
            skipped_lines += first == "\n"
            first = fh.read(1)
        if first == "[":
            try:
                data = json.loads(first + fh.read())
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path.name} is not valid JSON ({exc.msg}, line {exc.lineno + skipped_lines})"
                ) from exc
            data = data if isinstance(data, list) else [data]
            for i, r in enumerate(data, 1):
                yield _object(r, f"{path.name} item {i}")
            return
        # JSON Lines: one object per line, constant memory.
        buffer = first
        for line_no, line in enumerate(fh, 1 + skipped_lines):
            record = (buffer + line).strip()
            buffer = ""
            if record:
                try:
                    parsed = json.loads(record)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{path.name} line {line_no} is not valid JSON ({exc.msg}); fix or remove it"
                    ) from exc
                yield _object(parsed, f"{path.name} line {line_no}")


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
