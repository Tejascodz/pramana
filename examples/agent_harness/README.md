# Audit a real model acting as an agent

This harness runs a real open-weights model (Ollama by default) as a tool-using
fee-refund agent, records its reasoning and every tool call in Pramana's trace
schema, and hands the trace to the audit. It is the bridge from auditing a
hand-written log to auditing a real model's agent behaviour.

```bash
# 1. Ollama running with a model pulled (see the live_assistant example)
ollama pull llama3.2:3b

# 2. Run the model as an agent; it writes trace.jsonl here
python examples/agent_harness/run_agent.py --model llama3.2:3b --sessions 3

# 3. Audit what it did
pramana run examples/agent_harness/audit.yaml --out packs/live_agent
open packs/live_agent/report.html
```

The agent uses a text ReAct protocol (`THOUGHT: … / ACTION: … / FINAL: …`), so it
works with small local models that have no structured function-calling. The
`THOUGHT` line is recorded as the event's reasoning — exactly what
`agent.misalignment_signals` reads.

The scenario is an ordinary refund assistant, and the tools are local mocks with
no side effects. The harness does **not** pressure or trick the model; it records
what a real model does in a normal task. If the model behaves well, the audit
passes — that is the honest, and the good, outcome. Run several sessions
(`--sessions`) because model behaviour varies between runs.

Point it at any OpenAI-compatible endpoint with `--backend-url` and `--model`.
