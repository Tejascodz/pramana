# Changelog

## 0.2.5 — 2026-10-21

- CI actions updated to their current releases, still pinned by commit SHA: checkout 7.0.1, setup-python 7.0.0, upload-artifact 7.0.2
- Dependabot configuration removed; updates are applied directly to `main`

## 0.2.4 — 2026-10-21

Security review of the full repository and history (see SECURITY.md).

- Niva refuses requests a web page could make: DNS rebinding (non-localhost `Host`), cross-site requests (`Origin` header) and non-JSON bodies; requests are capped at 1 MB; errors no longer echo internal details; `--backend-url` must be http(s)
- The HTTP client refuses redirects, so keys are never resent to another server; responses are capped at 10 MB; credentials in URLs are refused
- `pramana verify` only reads files inside the pack; the dashboard shows pack text as plain text
- CI: actions pinned to commit SHAs (Dependabot keeps them current), checkout no longer persists the token, and the composite action passes inputs through environment variables
- Minimum versions raised above known advisories: Jinja2 3.1.6, scikit-learn 1.5
- The built-in probe packs are now tracked (they were excluded by an ignore rule)

## 0.2.3 — 2026-10-21

Hardening, see SECURITY.md.

- The dashboard listens on `127.0.0.1` only and sends no usage statistics (`.streamlit/config.toml`)
- The Niva reference app refuses to listen on a non-loopback address unless `--allow-remote` is given
- `${VAR}` is expanded in request headers only, never in URLs or request bodies
- Credentials are only sent over https or to this computer; only `http(s)` endpoints are accepted
- CI workflows run with a read-only token
- Tests for each of these, and for HTML escaping of hostile model output in the report

## 0.2.2 — 2026-10-21

Second real-model run (3 samples per probe, 258 calls), see docs/live-run-findings.md.

- Negation-aware `must_not_include` matching in conduct and groundedness probes
- Replay accepts the full transcript (`llm_transcript.json`) and keeps measured latency, so service health is scored on recorded runs; `llm_replay.jsonl` now records latencies too
- `--replay` on `pramana run` re-scores a recording without editing the spec
- Both real runs recorded under examples/live_assistant/recorded, with regression tests and re-scored packs

## 0.2.1 — 2026-10-21

Scoring fixes from the first real-model run (`llama3.2:3b`), see docs/live-run-findings.md.

- Marker matching across whitespace and one-character near-matches (flagged for review)
- Data canaries: `sensitive_records` / `sensitive_values` catch name and account-number leaks, scanned across every probe
- Groundedness fails on unsupported e-mail addresses, links and phone numbers, and on `must_not_include` contradictions
- Recorded real-model responses added as regression tests

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
