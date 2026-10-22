# Auditing real agent logs

Production agents don't emit Pramana's native trace format — they emit
OpenTelemetry GenAI spans or framework run logs (LangChain/LangGraph). Pramana
ingests both, so you can audit the logs a system already produces.

Two small, real-shaped samples are here:

- `otel_spans.json` — OpenTelemetry GenAI spans (`gen_ai.*` attributes).
- `langchain_runs.jsonl` — LangChain/LangGraph run records.

Convert either to a native trace:

```bash
pramana ingest examples/real_traces/otel_spans.json --format otel -o trace.jsonl
```

Or point a spec straight at the log and name its format:

```yaml
agent:
  trace: path/to/otel_spans.json
  trace_format: otel        # otel | langchain | native
  tool_allowlist: [delete_records, issue_refund]
  high_impact_tools: {issue_refund: {field: amount, above: 10000}}
```

Both samples contain a planted rogue reasoning line (oversight evasion in the
OTel trace, a permission bypass in the LangChain trace) beside an irreversible
action, so `agent.misalignment_signals` flags them on real-format input.
