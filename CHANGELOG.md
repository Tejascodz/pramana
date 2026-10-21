# Changelog

## 0.2.0 — 2026-10-21

Live red-teaming of LLM applications.

- Live adapters: `openai_compatible` and a generic `http` mode with body templates, response paths and `${ENV}` secrets; timeouts, retries with backoff, pre-flight check, per-call latency, model and error capture
- Repeated sampling (`--samples`) with worst-case probe results and Wilson 95% intervals
- Built-in probe library: 14 English injection probes, 8 Indic-language probes (Hindi, Hinglish, Kannada, romanised Kannada, Tamil), 5 disclosure probes; `include:` in probe files
- Judge-free scoring with split markers and regular expressions, secret-pattern detection, prompt-echo exclusion, and refusal-aware review flags
- New check `llm.service_health` (error rate, p50/p95 latency, output length)
- Audits with errored checks block the gate as incomplete; new *Incomplete* opinion
- Live packs include `llm_replay.jsonl` for offline, reproducible re-runs
- New commands: `pramana ping` and `pramana diff` (with `--fail-on-regression`)
- Report: live-run section, per-language results, samples failed per probe, held-out tags
- Reference application Niva (baseline and guarded builds) for live audits on a local model

## 0.1.0 — 2026-10-21

First public release.

- SMACTR audit engine with a hash-chained evidence ledger and `pramana verify`
- 19 checks across governance, data, performance, fairness, robustness, drift, transparency, privacy, LLM security and reliability, agent auditability and audit self-testing
- Control library: NIST AI RMF (72), NIST GenAI Profile (12), ISO/IEC 42001 Annex A (38), EU AI Act (17, tier-aware, Digital Omnibus dates), India AI Governance Guidelines and DPDP, OWASP LLM Top 10 (2025)
- EU AI Act tier classifier and India context-sensitivity rating
- Risk register, release gate, audit opinion, remediation plan
- Self-contained HTML report with light and dark themes, model card, CSV and JSON exports
- CLI, composite GitHub Action, Streamlit viewer
- Three case studies with planted defects and ground-truth tests
