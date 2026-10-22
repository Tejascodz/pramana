# Changelog

## 0.4.1 — 2026-10-23

Validated the misalignment detector on real agent trajectories, and fixed its precision.

- Ran `agent.misalignment_signals` over the Who&When benchmark (ag2ai, ICML 2025, MIT): 184 real multi-agent trajectories, ~4,000 messages. The first version produced 19 signals, almost all false positives (web-scraped "hide", company names, trivia, normal OAuth).
- Tightened the detector: polysemous patterns now require first-person agent intent, and hide/conceal/privilege patterns require a concrete object. Result: **0 false positives** on the same ~4,000 real messages, with every planted and real rogue example still firing.
- Bundled the converter and three attributed sample trajectories under `examples/benchmark_whowhen`, with a precision test in CI.

## 0.4.0 — 2026-10-23

Three production levers: signed evidence, a live-model agent harness, and streaming.

- **Signed evidence packs** (optional, `pip install "pramana[signing]"`): `pramana keygen`, `pramana sign` and signature-aware `pramana verify` (with `--public-key` to pin provenance and `--require-signature` for CI). Ed25519 over the ledger root and a ledger digest; signing refuses an already-tampered pack, and any later change breaks the signature.
- **Live-model agent harness** (`examples/agent_harness`): drives a real OpenAI-compatible model (Ollama/llama3.2:3b by default) through a benign tool-using task with a text ReAct protocol, records its reasoning and tool calls as a Pramana trace, and audits it — so the agent checks run against a real model's behaviour, not a hand-written log. Offline-tested with a scripted model.
- **Streaming scan** (`pramana scan-trace`): streams an agent log of any size in constant memory and reports misalignment signals, with `--fail-on-signal` for CI. Verified constant-memory on an 80k-event trace.

## 0.3.1 — 2026-10-23

Audit the logs real agent systems emit, and scale testing.

- New trace adapters: ingest **OpenTelemetry GenAI spans** and **LangChain/LangGraph run logs** and map them to Pramana's event schema (`src/pramana/adapters/traces.py`). Set `agent.trace_format: otel|langchain|native` in the spec, or convert with the new `pramana ingest` command.
- A misconfigured or unreadable trace now blocks the gate as an error instead of being silently skipped — an audit cannot vouch for evidence it could not parse.
- Example real-format traces under `examples/real_traces`, each demonstrating misalignment detection on converted input.
- Scale test: a ~12k-event trace is scanned in well under a second; limitations now document the in-memory bound and the session-batching path for production-volume logs.

## 0.3.0 — 2026-10-23

Agentic safety: a new check for agent misalignment, grounded in the 2026 literature.

- New check `agent.misalignment_signals`: scans an agent's reasoning traces and actions for the documented rogue patterns (self-preservation, deception, oversight evasion, goal substitution, privilege escalation, reward hacking), quotes the offending log line as proof, and flags sessions where a misalignment signal co-occurs with an irreversible action (the intent-plus-capability core of the loss-of-control model). Judge-free and deterministic; a clean scan is reported honestly, never as proof of safety. User-extensible via `agent.misalignment_patterns` in the spec.
- Mapped to NIST AI RMF (MEASURE/MANAGE), ISO/IEC 42001, OWASP LLM06 (excessive agency), EU AI Act Art. 14/15 and India's safety and accountability sutras.
- The refund-agent case study now includes a session that demonstrates detection.
- New `docs/agentic-safety-review.md`: a sourced 2026 review of AI safety regulation, governance, how agents go rogue, and how to control them, with the upgrade design this check implements.

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
