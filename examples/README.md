# Case studies

Each folder is a complete audit target with an `audit.yaml` spec. Defects are planted on purpose so you can see how Pramana reports them; the end-to-end tests use them as ground truth.

| Folder | System type | Setup |
|---|---|---|
| `credit_scoring/` | Tabular classifier | `python examples/credit_scoring/build_model.py` builds the synthetic data and model |
| `support_chatbot/` | LLM application | None. Recorded responses are replayed from `transcripts.jsonl` |
| `agent_traces/` | AI agent | None. The agent's action log is `refund_agent_trace.jsonl` |
| `live_assistant/` | Live LLM application | Ollama with a small model, then start the Niva app. See its README |
| `agent_sandbox/` | AI agent (live) | Ollama with a model that supports tool calling. Runs the real model through honeypot scenarios |
| `agent_harness/` | AI agent (live) | Ollama. Drives a model through one benign task and records a trace (`run_agent.py`) |
| `real_traces/` | AI agent | None. OpenTelemetry and LangChain logs, read with `trace_format` or `pramana ingest` |
| `benchmark_whowhen/` | AI agent | None. A sample of the Who&When benchmark used to check misalignment-signal precision |

Run any of them:

```bash
pramana run examples/<folder>/audit.yaml --out packs/<folder>
```

Nilgiri Finance, Niva and every person, account and number in these files are fictional.
