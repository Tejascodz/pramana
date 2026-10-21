# Sample audit packs

Complete audit packs for the three case studies, generated with `--date 2026-10-21`. All data is synthetic and the organisations are fictional.

| Pack | Open the report | Gate |
|---|---|---|
| [credit_scoring](credit_scoring) | `credit_scoring/report.html` | BLOCK |
| [support_chatbot](support_chatbot) | `support_chatbot/report.html` | BLOCK |
| [agent_traces](agent_traces) | `agent_traces/report.html` | BLOCK |

Download a `report.html` and open it in any browser; it is a single file with no external dependencies.

Check that a pack is intact:

```bash
pramana verify docs/sample-audits/credit_scoring
```

Try changing any file under `evidence/` and run the command again to see tampering detected.
