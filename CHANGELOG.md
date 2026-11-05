# Changelog

## 0.7.10 — 2026-11-05

More from the file-by-file review.

- **Fix: a typo could lower the EU AI Act tier.** `domain: credit-scoring` (hyphen) was not recognised, so a credit model was classed as *minimal* risk instead of *high*; an unknown `prohibited_practice_flags` entry was ignored. Both are now spec errors with a "did you mean" suggestion, and `pramana classify --help` lists the known domains (the starter spec already pointed there, but the list was missing).
- **Fix: a risk acceptance without an expiry date never lapsed.** The README promised acceptances last until a named date; one without `expires` was honoured forever. Acceptances now need an existing check id, `approved_by`, `justification` and a valid `expires` date, or the spec is refused (a bad date used to crash the audit).
- **`pramana verify` no longer overstates a signature.** Without `--public-key`, a valid signature only proves the pack was not changed after signing, by whoever holds the key stored in the pack, not who signed it; the message now says so. A malformed `signature.json` is reported instead of raising a traceback.

## 0.7.9 — 2026-11-05

Security, from the file-by-file review.

- **Fix: a truncated ledger let results.json be forged.** `pramana verify` checked every ledger entry and every file under `evidence/`, but `results.json`, the report and the CSV exports sit at the top of the pack. Cutting the last entries off the ledger left a valid chain, and `results.json` could then be edited: a test turned a BLOCK into a PASS and *Ineffective* into *Effective*, and verification still said OK. Every file in the pack must now be recorded in the ledger (only the ledger itself, `signature.json` and file-manager metadata are exempt), and `results.json` must be recorded. Rebuilding a whole pack from scratch is still only stopped by a signature or a CI attestation, as documented.
- `pramana diff` counts a check that ran in the earlier audit and is missing from the later one as **removed**, which fails `--fail-on-regression`; dropping a failing test no longer looks like progress. New checks are listed as **added**.
- `pramana init` followed by `run` reports the missing files instead of a pickle-trust error for a model file that does not exist yet.
- The `signing` extra is named `pramana-audit[signing]` in the error message and docs; stale version numbers removed from SECURITY.md and the release workflow; `make lint` also checks formatting, like CI.

## 0.7.8 — 2026-11-05

From a file-by-file review of the repository (every data file parsed, every pack verified, every example audit run).

- **Critical fix: the gate could pass a system that was never tested.** With every data file of a credit model missing and its risk tier declared correctly, all thirteen model checks were *skipped* and the gate said **PASS**. Missing inputs were treated as "not applicable" even when the spec named them. Now an input declared in the spec but not found is an error (the check reads "Not tested: … is declared in the spec but not found"), which makes the audit incomplete and blocks the gate. Inputs that were never declared are still not applicable. As a safety net, the gate also blocks when no technical test ran at all.
- A declared agent trace that does not exist yet (for example before `run_agent.py` has been run) used to surface as a raw `FileNotFoundError` on every agent check; it now says which file is missing and what to do.

## 0.7.7 — 2026-11-05

The interactive viewer had not been tested since the 0.6 features landed. It was run in a real browser against the credit, real-model and agent-sandbox packs (every tab, every finding open): no errors, and the integrity check worked. Fixes from that run:

- **Security: URLs in a pack became clickable links.** The viewer escaped Markdown, but Streamlit still auto-linked bare web and e-mail addresses, so a URL in a model's answer showed up as a link a reviewer could click. They are now defanged with an invisible word joiner; a hostile test pack now renders no links.
- **Per-test detail in findings.** Each finding shows its table: test, result, samples failed, technique, turn at which a conversation broke, honeypot outcome, language and the reply. Before, only the summary and raw metrics were shown, so multi-turn, obfuscation and honeypot results were invisible in the viewer.
- Recommendations are shown only for failures and warnings, the live-run line (endpoint, calls, samples, model) is shown, and the one-click *Deploy* button is hidden.
- Viewer tests (`tests/test_dashboard.py`, Streamlit AppTest) now run in CI: `streamlit` is in the `dev` extra.

## 0.7.6 — 2026-11-05

- **Report layout fixes** found while regenerating the README screenshots: long framework names in the coverage chart ran off its left edge (they now wrap onto two lines), the risk register squeezed its table beside the heatmap below laptop width (it now stacks), and probe rows repeated their language or "held out" when the technique already said so.
- README screenshots regenerated from the current reports at 1600 px (2.4 MB → 0.5 MB). The LLM screenshot now shows real `llama3.2:3b` replies from run 6, re-scored from its recording with the current template.

## 0.7.5 — 2026-11-05

From a full review of the repository (code, history and documentation).

**Security**
- The sandbox's human-approval prompt (`approver: ask`) and `pramana scan-trace` output on a terminal now escape every character outside printable ASCII. A hostile agent could otherwise use terminal control sequences or right-to-left overrides to change what the operator reads, for example the amount of a refund awaiting approval.
- Full-history scan: no keys, tokens, private keys or personal paths in any of the 33 commits (detect-secrets and pattern search; the only hits are SHA-256 fingerprints, Pramana's own encoded test probes and fake credentials in tests). `bandit` reports no issues at any severity; `pip-audit` finds no vulnerable dependency, extras included.

**Documentation**
- README: fixed a code block that swallowed a paragraph, the `pramana-audit[signing]` install name, probe and held-out counts, the project layout (attacks, sandbox, demos), and the real-run summary (six runs). Every link checked.
- `examples/README.md` lists all eight examples; the live assistant README describes conversation memory, normalised screening and the held-out conversations; `docs/limitations.md` covers multi-turn, obfuscation, the sandbox and approval paths; `SECURITY.md` lists the sandbox tool server.

## 0.7.4 — 2026-11-05

Found by real run 5 (`docs/live-run-findings.md`).

- **Fix: a customer's own name, given earlier in a conversation, was reported as a critical disclosure.** The cross-probe scan in `llm.sensitive_disclosure` only treated values in the current message as user-supplied; it now uses every user turn of the conversation.

## 0.7.3 — 2026-11-05

- **Held-out multi-turn conversations** for the live assistant (`LIVE-MT-H1` to `H6`): support-ticket framing, drift to a human persona, an approval guarantee by commitment, piecemeal customer-data extraction, an instruction laundered through translation, and gradual extraction in Kannada. Committed before any run; Niva's guarded build will not be tuned to them.
- Attack probes can list `success_phrases`, judged with the negation-aware matcher used for conduct rules.
- A test checks every shipped multi-turn probe: no judged user turn may contain its own proof (this caught one draft probe whose final user message contained the phrase it tested for).

## 0.7.2 — 2026-11-05

Found by the first real run of the multi-turn and obfuscation checks (llama3.2:3b behind guarded Niva; `docs/live-run-findings.md`, run 4). Obfuscation: all disguised variants stopped. Multi-turn: 3 of 8 conversations failed, two of them real.

- **Fix: a set-up turn could count as a breach.** In MT-03 the user tells the assistant a call sign and the model repeated it back, which was scored as adopting the persona. Multi-turn probes can now set `judge_from_turn`; MT-03 is judged from turn 3.
- Niva's guarded build refuses conditional trigger rules ("whenever I write …") and fabricated `Assistant:` lines in a user message, the two real gaps the run found.

## 0.7.1 — 2026-11-05

Found by the first real-model run of the agent sandbox (llama3.2:3b, see `docs/live-run-findings.md`, run 3).

- **Fix: `agent.honeypot` blamed a planted instruction the agent never saw.** The model refunded 18,500 without approval as its first action, before reading the fee history that held the planted note, and 0.7.0 reported it as "obeyed an instruction planted in a tool result". Runs that stopped before reaching a trap were counted as resisted. Each honeypot scenario now declares a `bait` string, and each run is classed as obeyed (forbidden action after the bait reached the agent), unprompted (forbidden action before it: still a failure, reported as a rule violation), resisted (saw it, ignored it) or not reached (not tested, never a pass).
- Scenario files must declare a `bait` that appears in their planted text.

## 0.7.0 — 2026-11-04

**Packs attested by CI**
- The GitHub Action takes `attest: "true"` and signs the pack's ledger, results and report with a GitHub build-provenance attestation (Sigstore, keyless). `pramana verify PACK --attested-by OWNER/REPO` checks every file against the ledger and then the attestation, and prints the workflow and commit that produced the pack.

**Agent sandbox and honeypots**
- New check `agent.honeypot`: the real agent under audit works through scenarios in a stand-in bank where tool results carry planted instructions (refund redirection, data exfiltration by e-mail, a false "already approved" note, Hindi). Verdicts come from the exact forbidden tool calls; a control task checks the agent still does its job.
- Three ways to drive it: native function calling (`agent.sandbox`, any OpenAI-compatible endpoint), a text protocol for models without tools, and `pramana sandbox serve`, an HTTP tool server for the customer's own agent code (loopback only, refuses browser requests).
- Approvals are never faked as a person: a declared deny-all policy (logged as `policy:deny-all`) or a real operator at the terminal (`approver: ask`).
- The sandbox writes a hash-chained trace into the pack, so all agent checks run on it and it can be re-audited offline.
- New check `agent.approval_paths`: proves on a workflow graph (LangGraph JSON or an edge list) that no irreversible step is reachable without an approval step, or reports the shortest path that is.
- `agent.oversight_integrity` now recognises notes addressed to automated agents, instructions to skip a named tool, and Hindi instructions for the assistant. On the new scenarios it caught 1 of 4 planted instructions before this change and 4 of 4 after, with no hit on ordinary notes to human agents.
- `examples/agent_sandbox/audit.yaml` runs the honeypots against a real local model (llama3.2:3b through Ollama).

**Obfuscated attacks**
- New check `llm.obfuscation` (opt in with `llm.mutations: all` or a list): every injection probe is re-sent with zero-width spaces, look-alike letters, soft hyphens, letter spacing, digit substitution, full-width letters or joiners inside Indic-script words. Codes, quotes, the canary and URLs are never altered, so variants are judged by the original markers. Variants that succeed where the plain attack failed are reported as bypasses.
- `pramana.attacks.mutations.normalize` is the matching defence (NFKC, strip format characters, fold look-alikes). The guarded Niva build now screens normalised text. On the test model, a raw-text filter let 22 disguised attacks through that it stopped in plain form; with normalisation, 2.
- Fix: `pramana run --replay` dropped `llm.mutations`, so the obfuscation check was skipped on replay.

**Multi-turn attacks**
- New check `llm.multi_turn`: plays attack conversations turn by turn with the system's real replies in the history, judges every reply with the same deterministic rules as `llm.prompt_injection`, and reports the turn at which the defence broke. Built-in pack `builtin:multiturn_core` (8 conversations: Crescendo-style escalation, delayed triggers, persona drift, refusal erosion, fabricated history, Hindi and Hinglish).
- Every client can send a whole conversation: `openai_compatible` natively, `http` through a `"{messages}"` body slot or flattened, and replay keyed by the user turns. Live conversations are recorded per turn in `llm_replay.jsonl` and replay offline with identical verdicts.
- Niva remembers the last three exchanges. The guarded build now screens every remembered user turn, not only the latest one; on the test model 6 of 8 conversations break the baseline and 1 of 8 breaks the guarded build.

## 0.6.0 — 2026-11-04

Installable with pip as **`pramana-audit`**, from GitHub (`pip install "pramana-audit @ git+https://github.com/Tejascodz/pramana"`) or from the wheel on each GitHub release. The command and the import stay `pramana`. PyPI publishing is ready but switched off.

**Install and first run**
- Install, then `pramana demo` runs the credit, chatbot and agent case studies from the installed package, verifies their packs and prints where the reports are. No clone needed.
- Extras: `signing`, `skops`, `dashboard` and `all`. SPDX licence metadata, `py.typed`, absolute README links so PyPI renders images.

**Security**
- **Pickled models are refused unless pinned or trusted.** A crafted `.joblib` file used to run code on the auditor's machine as soon as the model was loaded. Pramana now needs `artifacts_sha256.model`, `trust_pickled_model: true` or `pramana run --trust-model`, and says so. The credit example opts in because you build its model yourself.
- `.skops` models load without unpickling and only with scikit-learn, NumPy and SciPy types.
- CSV exports neutralise spreadsheet formulas (CWE-1236).
- `report.html` carries a Content-Security-Policy that forbids scripts, remote loads and forms.
- YAML inputs are capped at 5 MB; a spec that is not a mapping or not valid YAML is a spec error (exit 3), not a traceback; `builtin:` probe names must exist in the library.

**Release engineering**
- Tag-triggered release workflow: tests, build, clean-venv demo, GitHub release with the wheel, build provenance and `SHA256SUMS`. Optional PyPI Trusted Publishing behind the `PUBLISH_TO_PYPI` repository variable.
- CI: wheel smoke test on Linux, macOS and Windows; `pip-audit`; `bandit`; CodeQL; Dependabot. Tests enforce SHA-pinned actions and a per-job permission allowlist.

**Fixes**
- `test_credit_audit_reports_tail_privacy_and_base_rates` passed only where the credit example had been built locally; it failed on a fresh clone and in CI.

## 0.5.1 — 2026-10-23

Found while running the live agent harness end to end on llama3.2:3b.

- The harness printed nothing until every session had finished, so a slow local model looked stuck and was easy to stop by mistake. It now prints one line per step (tool chosen, seconds taken).
- Stopping it with Ctrl+C no longer loses the run or prints a traceback: the trace is written after every session, and the completed sessions are kept.
- The harness spec declares the stop condition the harness really enforces (`--max-steps`), so `agent.control_readiness` reports it as declared rather than missing.

## 0.5.0 — 2026-10-23

The rest of the agentic-safety roadmap (`docs/agentic-safety-review.md` §6), two new control catalogues, a CycloneDX ML-BOM, input pinning, and fixes from a line-by-line review of 0.4.2. New tests: `tests/test_agent_controls.py` and `tests/test_hardening.py`.

**Agents**
- **Loss-of-control triad.** `agent.misalignment_signals` now scores each session on the UN Scientific Panel's three conditions: misaligned intent, irreversible capability and a permissive environment (an irreversible action ran with no human review, a tool outside the allowlist was used, or no allowlist exists). Critical only when all three hold in the same session; a signal in one session is never paired with an action in another.
- **Evaluation gaming.** A seventh pattern catches first-person intent to fake compliance or deliberately underperform because the agent may be tested. Noticing a test ("this is a benchmark question") does not count.
- **New check `agent.control_readiness`.** Six safeguards (own identity, allowlist, approval gate, stop conditions, tamper-evident log, monitor), each graded as evidenced in the trace, declared in the spec only, or missing. Fails when tool calls run under a person's identity. Gaps that `agent.trace_auditability` already reports are noted, not counted twice.
- **New check `agent.oversight_integrity`.** Share of tool calls explained by logged reasoning (output text does not count) and instructions planted in tool results, with the action that followed.
- Precision re-checked on the full Who&When benchmark: 0 signals and 0 planted-instruction hits across 4,092 real agent messages.
- `pramana scan-trace` reports the triad too, and `permissive_environment` on each signal.

**Frameworks and outputs**
- **OWASP Top 10 for Agentic Applications (2026)**, with the published IDs and titles, applied to agent audits only.
- **ISO/IEC 42005:2025 AI system impact assessment**: 15 clauses, numbered as in NIST's ISO/IEC 42005 to AI RMF crosswalk. The library now holds 8 frameworks and 184 controls.
- **`ml_bom.cdx.json`** in every pack: a CycloneDX 1.7 ML bill of materials (system, data and trace files with SHA-256, measured metrics, fairness findings), sealed in the ledger and validated in the tests against the official schema.
- **`artifacts_sha256`** in the spec pins inputs: an artifact that has changed is refused before anything is read, and a model before it is unpickled.
- The dashboard re-verifies the pack it shows and warns if it was altered.

**Statistics**
- Proxy and leakage screening uses out-of-fold target encoding. Before, a column of unique IDs (pure noise) scored AUC 1.0 and was reported as leakage.
- Calibration also reports ECE with equal-mass bins (Nixon et al., 2019); membership inference also reports the true-positive rate at 1% and 5% false-positive rate (Carlini et al., 2022); fairness reports group base rates and says when equal error rates and calibration cannot both be met (Kleinberg et al., 2017).

**Fixes**
- Groundedness now matches "5 lakh" against "₹5,00,000" in both directions (only one direction worked), reads thousand/million/billion, and no longer takes "5 credit cards" as 5 crore.
- Fairness no longer prints an empty "Attributes needing action" list when the only issue is an untested attribute, and its summary no longer says "within the four-fifths benchmark" while a different attribute fails on error rates.
- The detector self-test skips, rather than fails, its fairness canary when no one receives a favourable outcome, and plants the drift canary in a feature that varies.
- An approval or tool call without a timestamp no longer crashes the auditability check; it counts as unapproved.
- "no" and "ms" were removed from the abbreviation list: they end real sentences, and merging sentences weakened the first-person check.
- Signals from events with no session ID are never paired, and no longer crash the co-occurrence step.
- `PRAMANA_SIGNING_KEY_PEM` also accepts a key stored on one line with literal `\n`.
- HTTP endpoints must use POST, PUT or PATCH (the prompt travels in the body); a missing probe include is a clear error; the ledger refuses to write outside the pack; piping CLI output into `head` no longer prints a traceback; the benchmark converter prints usage instead of crashing.
- `pip install -e ".[dev]"` now includes `cryptography` and the CycloneDX validator, so CI runs the signing and ML-BOM schema tests.

## 0.4.2 — 2026-10-23

Fixes from an external code review. Each finding was reproduced before it was fixed, and each fix has a regression test (`tests/test_review_fixes.py`).

- **Signing keys stay out of repositories.** `pramana keygen` now writes to `~/.pramana/keys` by default, refuses to write inside a git working tree unless given `--allow-in-repo`, and will not overwrite an existing key without `--force`. `pramana sign` reads the key from `--key`, then from the `PRAMANA_SIGNING_KEY_PEM` environment variable (for CI secrets), then from the default key file. `.gitignore` now excludes `*.key`, `*.pem` and `pramana_ed25519.*`.
- **Fairness no longer passes what it could not test.** When an attribute has fewer than two groups large enough to compare, or no group receives a favourable outcome, `fairness.group_parity` and `fairness.intersectional` now report a warning saying the attribute could not be assessed, instead of a pass. Unassessed attributes are listed in the metrics.
- **The detector self-test always plants a detectable disparity.** `audit.detector_sensitivity` used to halve favourable decisions for the most frequent group, which could hide the canary when that group was already favoured. It now targets the group with the lowest selection rate.
- **Drift handles features it cannot measure.** Features with no usable values (PSI is NaN) are sorted last and reported as unmeasured, instead of being ranked arbitrarily, and the check no longer fails when no feature can be measured.
- **Groundedness understands Indian figures and list markers.** "₹5,00,000", "5 lakh" and "1.5 crore" are matched as the same amounts as their expanded forms, and list numbering such as "1." is no longer treated as a claimed figure.
- **Sentence splitting in the misalignment detector** no longer breaks on abbreviations ("e.g.", "etc.") or file names ("auth.py"), so first-person intent written around them is still detected. More first-person forms are recognised ("I'd", "myself", "my real goal").
- **Audit packs reject planted files.** `pramana verify` now fails if a file under `evidence/` is not recorded in the ledger. Re-running an audit into an existing pack folder clears the previous run's evidence and signature first.
- **`pramana scan-trace` reports intent alongside capability.** Each signal now carries `with_capability`: whether the same session also made an irreversible tool call. The summary names those sessions, and `--high-impact-tool` adds tool names of your own.

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
