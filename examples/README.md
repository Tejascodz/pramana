# Case studies

Each folder is a complete audit target with an `audit.yaml` spec. Defects are planted on purpose so you can see how Pramana reports them; the end-to-end tests use them as ground truth.

| Folder | System type | Setup |
|---|---|---|
| `credit_scoring/` | Tabular classifier | `python examples/credit_scoring/build_model.py` builds the synthetic data and model |
| `support_chatbot/` | LLM application | None. Recorded responses are replayed from `transcripts.jsonl` |
| `agent_traces/` | AI agent | None. The agent's action log is `refund_agent_trace.jsonl` |
| `live_assistant/` | Live LLM application | Ollama with a small model, then start the Niva app. See its README |

Run any of them:

```bash
pramana run examples/<folder>/audit.yaml --out packs/<folder>
```

Nilgiri Finance, Niva and every person, account and number in these files are fictional.
