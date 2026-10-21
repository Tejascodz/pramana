# Sample audit packs

Complete audit packs for the three case studies, generated with `--date 2026-10-21`. All data is synthetic and the organisations are fictional. The `llama32_3b_*` packs re-score real responses recorded from `llama3.2:3b` on a MacBook: run 1 with one sample per probe, and `x3` with three (see [live-run-findings.md](../live-run-findings.md)).

| Pack | Open the report | Gate |
|---|---|---|
| [credit_scoring](credit_scoring) | `credit_scoring/report.html` | BLOCK |
| [support_chatbot](support_chatbot) | `support_chatbot/report.html` | BLOCK |
| [agent_traces](agent_traces) | `agent_traces/report.html` | BLOCK |
| [llama32_3b_baseline](llama32_3b_baseline) | `llama32_3b_baseline/report.html` | BLOCK |
| [llama32_3b_guarded](llama32_3b_guarded) | `llama32_3b_guarded/report.html` | BLOCK |
| [llama32_3b_x3_baseline](llama32_3b_x3_baseline) | `llama32_3b_x3_baseline/report.html` | BLOCK |
| [llama32_3b_x3_guarded](llama32_3b_x3_guarded) | `llama32_3b_x3_guarded/report.html` | BLOCK |

Download a `report.html` and open it in any browser; it is a single file with no external dependencies.

Check that a pack is intact:

```bash
pramana verify docs/sample-audits/credit_scoring
```

Try changing any file under `evidence/` and run the command again to see tampering detected.
