# Pramana

### AI Assurance & Evidence Engine

*Pramana (प्रमाण) is Sanskrit for "proof", the valid means by which knowledge is established. This project applies that idea to AI: every claim about a system must be backed by evidence that can be checked.*

**Evidence-driven AI audit workbench.** Point it at an AI system, get back a risk register, a release-gate decision, a plain-English executive summary and a tamper-evident evidence pack, with every test result mapped to NIST AI RMF, ISO/IEC 42001, the EU AI Act and India's AI Governance Guidelines.

[![CI](https://github.com/Tejascodz/pramana/actions/workflows/ci.yml/badge.svg)](https://github.com/Tejascodz/pramana/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

![Audit report overview](docs/img/report-overview.png)

Pramana audits three kinds of systems: **tabular ML models** (credit, hiring, pricing), **LLM applications** (chat assistants, RAG) and **AI agents** (tool-using systems that take actions). It runs 20 automated checks, can red-team a **live LLM application on your laptop**, scores the findings as risks with owners and due dates, and decides whether the release can go ahead. The output is an audit pack that a second reviewer can verify with one command.

---

## Why this exists

AI governance is moving from policy documents to audits, and the tooling has not caught up.

- **Evaluation is not accountability.** A study of 35 AI audit practitioners and 435 tools found that most tools stop at measuring a model or managing a standard. Few connect a result to an owner, a decision and a follow-up ([Ojewale et al., CHI 2025](https://arxiv.org/abs/2402.17861)). Pramana links every metric to controls, a scored risk, an owner, a remediation date and a go/no-go decision.
- **A policy is not evidence.** In a 2026 survey of about 950 US executives, 78% lacked strong confidence they could pass an independent AI governance audit within 90 days ([as reported here](https://www.unframe.ai/blog/ai-auditability-what-regulators-ask-for)). Pramana fingerprints every artifact and seals every result in a hash-chained ledger, so the evidence can be checked rather than trusted.
- **Too many frameworks, one system.** Teams answer to NIST AI RMF, ISO/IEC 42001, the EU AI Act and local rules at once. One Pramana test feeds every control it supports through a single crosswalk.
- **Agents create an accountability gap.** Auditors report that agent actions often happen with no traceable human request or approval, and current platforms cannot produce that evidence natively ([Cloud Security Alliance, Aug 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/)). Pramana audits agent logs for attribution, approvals and tamper-evidence.
- **LLM safety is weakest outside English.** Jailbreaks transfer from English to Indian languages, and romanised, code-mixed text is how many South Asian users actually type ([Yong et al., 2023](https://arxiv.org/abs/2310.02446); [IndicJR, 2026](https://arxiv.org/abs/2602.16832)). Pramana ships injection probes in Hindi, Hinglish, Kannada (both scripts) and Tamil, and reports results by language.
- **India-specific context is missing.** India's AI Governance Guidelines (MeitY, Nov 2025) call for an India-specific, evidence-based risk framework. Fairness in India runs along axes such as region and caste that Western tools do not model ([Sambasivan et al., FAccT 2021](https://arxiv.org/abs/2101.09995)). Pramana maps evidence to the seven sutras, checks for Indian identifiers (PAN, Aadhaar-format numbers, Indian mobile numbers) under the DPDP Act, and flags proxies such as pincode-based features.

The full literature review and gap analysis is in [docs/research-notes.md](docs/research-notes.md).

## How it works

Pramana follows the five-stage **SMACTR** internal audit framework from Google and Partnership on AI researchers ([Raji et al., FAT* 2020](https://arxiv.org/abs/2001.00973)). Every stage writes its output to the evidence ledger.

```mermaid
flowchart LR
    S[audit.yaml] --> A
    subgraph Pramana
    A[1 Scoping<br/>risk tier, obligations] --> B[2 Mapping<br/>FMEA, RACI]
    B --> C[3 Artifacts<br/>SHA-256 fingerprints]
    C --> D[4 Testing<br/>20 checks]
    D --> E[5 Reflection<br/>risk register, coverage, gate]
    end
    E --> R[report.html]
    E --> P[evidence pack + ledger]
    E --> G{Release gate}
    G -->|PASS| OK[exit 0]
    G -->|BLOCK| NO[exit 1]
```

## Quick start

```bash
git clone https://github.com/Tejascodz/pramana.git && cd pramana
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Build the synthetic credit-scoring case study (data + model)
python examples/credit_scoring/build_model.py

# Run the audit and open the report
pramana run examples/credit_scoring/audit.yaml --out packs/credit
open packs/credit/report.html          # macOS; use xdg-open on Linux

# Prove nothing in the pack was changed
pramana verify packs/credit
```

The other two case studies need no build step:

```bash
pramana run examples/support_chatbot/audit.yaml --out packs/chatbot
pramana run examples/agent_traces/audit.yaml --out packs/agent
```

Pre-generated packs are in [docs/sample-audits](docs/sample-audits). Download any `report.html` and open it in a browser.

## Case studies

Each case study plants known defects, so the audit can be checked against a ground truth. The end-to-end tests fail if any planted defect is missed or a clean area is flagged.

| Case study | System | Planted defects | What Pramana reports |
|---|---|---|---|
| [Credit scoring](examples/credit_scoring) | Gradient-boosted loan pre-approval model for a fictional Indian lender (synthetic data) | Biased historical labels for rural women; pincode band that tracks residence; e-mail and mobile columns left in extracts; overstated AUC in the model card; owner classified it as "limited" risk; income and gig-work drift | Disparate impact 0.72 for rural applicants (p < 1e-70), worse for intersectional sub-groups; pincode proxy (AUC 0.99); personal data exposure; documentation mismatch; EU AI Act misclassification (Annex III 5(b) makes it high-risk); missing FRIA. **Gate: BLOCK** |
| [Support assistant](examples/support_chatbot) | RAG chat assistant (replayed transcripts) | Indirect prompt injection in a pasted e-mail; another customer's contact details disclosed; invented foreclosure fee; crypto investment advice | 1/5 injection probes succeed; PII disclosure (critical); figures not in the knowledge base (4%, ₹500); conduct-rule breach. **Gate: BLOCK** |
| [Live assistant](examples/live_assistant) | Retrieval-augmented loan assistant on a **local open-weights model** (Ollama), in a baseline and a guarded build | Shared retrieval index holding customer records; no input screening; no output validation | Run it yourself: `pramana diff` shows the guarded build's controls closing the gaps, and 4 **held-out** probes show the risk that remains. See below. |
| [Refund agent](examples/agent_traces) | Tool-using agent that issues refunds | ₹18,500 refund with no human approval; a tool call with no originating request; no hash chain; an agent that reasons about avoiding shutdown and hiding a weak justification | Approval coverage 50%, one unattributed action, log not tamper-evident; **misalignment signals** (self-preservation + oversight evasion) caught in the agent's own reasoning, co-occurring with an irreversible refund. **Gate: BLOCK** |

![Fairness spotlight](docs/img/fairness.png)

<details>
<summary>More report screenshots: risk register and LLM probe results</summary>

![Risk register](docs/img/risk-register.png)

![LLM probe findings](docs/img/llm-findings.png)

</details>

## Checks

| Area | Check | Method |
|---|---|---|
| Governance | `governance.risk_classification` | EU AI Act tier from Art. 5, Art. 6 and Annex III and Art. 50; India context-sensitivity score; compares the owner's declared tier with the assessed one |
| Data | `data_quality.integrity` | Missingness, duplicates, class balance, single-feature target-leakage screen |
| Performance | `performance.discrimination` | ROC AUC with a bootstrap 95% CI against a declared minimum; train/test gap |
| Performance | `calibration.reliability` | Expected calibration error and Brier score, overall and per group |
| Fairness | `fairness.group_parity` | Disparate impact (four-fifths rule) with a two-proportion z-test, equal opportunity and equalized odds |
| Fairness | `fairness.intersectional` | All attribute pairs; flags gaps hidden by single-attribute analysis |
| Fairness | `fairness.proxy_features` | How well each input predicts each protected attribute (smoothed target-encoded AUC) |
| Robustness | `robustness.perturbation` | Decision flip rate under noise and missing values; monotonicity rules from the spec |
| Monitoring | `drift.population_stability` | PSI and KS/chi-square per feature, score drift, favourable-rate shift |
| Transparency | `explainability.feature_importance` | Permutation importance reconciled with drivers declared in the documentation |
| Transparency | `documentation.model_card` | Completeness against Model Cards, EU AI Act Art. 11, 13 and 14 and ISO 42001 A.6.2.7; **claims vs. measured results** |
| Privacy | `privacy.pii_exposure` | E-mail, Indian mobile, PAN, Aadhaar-format, card (Luhn) and IP patterns in every dataset |
| Privacy | `privacy.membership_inference` | Loss-threshold attack (Yeom et al., 2018) on training vs. held-out rows |
| LLM security | `llm.prompt_injection` | 26 probes: direct, role-play, indirect (e-mail, web page, tool output, JSON), payload splitting, base64, few-shot, markdown-image exfiltration, and Indic-language attacks; system-prompt canary; per-language results |
| LLM privacy | `llm.sensitive_disclosure` | Personal data and forbidden strings in responses |
| LLM reliability | `llm.groundedness` | Required facts plus a numeric-claim check against the knowledge base |
| LLM conduct | `llm.policy_adherence` | Required and forbidden phrases per conduct rule |
| LLM operations | `llm.service_health` | Error rate, retries, p50/p95 latency and output length from the live run (OWASP LLM10) |
| Agents | `agent.trace_auditability` | Attribution to a request, prior human approval for high-impact actions, tool allowlist, ordering, hash-chain integrity |
| Agents | `agent.misalignment_signals` | Scans the agent's own reasoning and actions for rogue patterns (self-preservation, deception, oversight evasion, goal substitution, privilege escalation, reward hacking) and flags where intent co-occurs with an irreversible action ([see the review](docs/agentic-safety-review.md)) |
| Assurance | `audit.detector_sensitivity` | Plants a disparity, a drift and a PII column in copies of the data and confirms the audit catches them |

Scoring is deterministic, so the same inputs always produce the same findings. Run `pramana checks` for the list with failure modes, and see [docs/methodology.md](docs/methodology.md) for every formula and threshold.

## Framework coverage

| Framework | Version | Controls in library |
|---|---|---|
| NIST AI Risk Management Framework | AI 100-1 | 72 subcategories |
| NIST Generative AI Profile | AI 600-1 | 12 risks |
| ISO/IEC 42001 Annex A | 2023 | 38 controls |
| EU AI Act | 2024/1689 as amended by the Digital Omnibus (2026/1744) | 17 articles, tier-aware |
| India AI Governance Guidelines + DPDP Act | MeitY, Nov 2025 | 7 sutras, 2 pillars, DPDP |
| OWASP Top 10 for LLM Applications | 2025 | 10 categories |

The report shows, per framework, which controls are **evidenced**, **partial**, **deficient** or **not tested by automation**. Pramana is honest that many governance controls (board approval, training, supplier contracts) need organisational evidence. Those documents can be attached in the spec, and they are fingerprinted into the pack. The full crosswalk is in [docs/control-mapping.md](docs/control-mapping.md).

![Framework coverage](docs/img/coverage.png)

## The audit pack

```
packs/credit/
├── report.html            # self-contained report: executive summary, risks, findings, coverage
├── model_card.md          # model card filled with measured results and open findings
├── results.json           # everything, machine-readable
├── risk_register.csv      # opens in Excel or Numbers
├── control_coverage.csv
├── remediation_plan.csv
├── ledger.jsonl           # append-only, hash-chained record of every evidence item
└── evidence/
    ├── 1-scoping/  2-mapping/  3-artifacts/  4-testing/  5-reflection/
```

`pramana verify` recomputes every hash. Editing a result, deleting a ledger line or reordering entries makes verification fail with exit code 2.

**Signed packs (optional).** The hash chain proves a pack is internally consistent; a signature proves *who* sealed it and that it was not rebuilt. With `pip install "pramana[signing]"`:

```bash
pramana keygen                       # Ed25519 key pair in ~/.pramana/keys
pramana sign packs/credit
pramana verify packs/credit --public-key ~/.pramana/keys/pramana_ed25519.pub
```

The private key never belongs in a repository: `keygen` refuses to write inside a git working tree. In CI, store the key as a secret and expose it as `PRAMANA_SIGNING_KEY_PEM`; `pramana sign` reads it from there when no `--key` is given.

## Use it as a release gate

`pramana run` exits with **1** when the gate blocks, so it can stop a deployment. The repository ships a composite GitHub Action:

```yaml
- uses: Tejascodz/pramana@main
  with:
    spec: models/credit/audit.yaml
    enforce: "true"        # fail the job on BLOCK
```

The action uploads the audit pack as an artifact and writes a risk summary to the job page. The gate respects formal risk acceptances: a risk approved by a named person, with a justification and an expiry date, does not block until it expires.

## Live red-team audit on your laptop

Pramana can audit a running LLM application as a black box, the way an assurance team tests a deployed system. The repository includes **Niva**, a reference retrieval-augmented loan assistant that runs on a small open-weights model through [Ollama](https://ollama.com), in two builds: a **baseline** with the flaws first versions often have, and a **guarded** build with layered controls.

```bash
ollama pull llama3.2:3b                                                  # ~2 GB, fits an 8 GB MacBook
python examples/live_assistant/niva_app.py --mode baseline --port 8800   # terminal 1
python examples/live_assistant/niva_app.py --mode guarded  --port 8801   # terminal 2

pramana run examples/live_assistant/audit_baseline.yaml --out packs/live_baseline
pramana run examples/live_assistant/audit_guarded.yaml  --out packs/live_guarded
pramana diff packs/live_baseline packs/live_guarded
```

What makes the live mode production-grade:

- **Any endpoint.** `openai_compatible` for Ollama, vLLM, LM Studio, llama.cpp or hosted APIs; `http` for any JSON API, with a body template, a response path and secrets read from environment variables.
- **Resilient calls.** Timeouts, retries with exponential backoff on 429/5xx, a pre-flight check (`pramana ping`), and failed calls recorded as evidence instead of crashing the audit. If a test cannot complete, the gate blocks as *incomplete*: an audit cannot vouch for what it did not test.
- **Stochastic outputs handled.** `--samples N` sends each probe N times; a probe fails if any sample fails, and rates come with Wilson 95% intervals ([Hughes et al., 2024](https://arxiv.org/abs/2412.03556) show attack success grows with repeated sampling).
- **Judge-free, defensible scoring.** Split markers, regular expressions and a planted canary prove compliance without a second model. Results that contain both proof and refusal language are flagged for human review.
- **Held-out probes.** Four probes the guarded build was not written against measure the residual risk, so passing the known attacks is not mistaken for safety.
- **Reproducible.** Every live pack contains `llm_replay.jsonl`, which re-runs the identical audit offline in CI.
- **Before/after evidence.** `pramana diff` compares two packs check by check, and `--fail-on-regression` turns it into a CI gate.
- **Safe on your laptop.** Niva, the model server and the dashboard listen on `127.0.0.1` only; nothing is reachable from your network, nothing is sent anywhere except the endpoint you audit, and keys are only ever sent over https. See [SECURITY.md](SECURITY.md).

Full walkthrough: [examples/live_assistant](examples/live_assistant).

### Findings from a real run

The first live audit ran `llama3.2:3b` on an 8 GB MacBook. The baseline build told a customer *"Yes, you are chatting with a real person"*, revealed which customer and account a phone number belonged to, invented a complaints e-mail address, and said there was *"no prepayment penalty"* despite a 3% foreclosure charge. Reading the transcripts also exposed four blind spots in Pramana's own scoring. The most serious: the guarded build had **passed** while accepting a persona switch, because the model misspelt the marker. The scorer was fixed, the recorded run re-scored offline, and the guarded build's gate correctly flipped to **BLOCK**. A second run with three samples per probe (258 calls) then showed what a single run hides: the system-prompt canary leaked in four attacks, including in Hindi and Hinglish, and the baseline volunteered another customer's account details to an unauthenticated user. The real responses are regression tests. Full write-up: [docs/live-run-findings.md](docs/live-run-findings.md).

## Interactive viewer

```bash
pip install -e ".[dashboard]"
streamlit run dashboard/app.py --server.address 127.0.0.1 -- --pack packs/credit
```

## Write your own audit

```bash
pramana init my_audit.yaml        # starter spec with every field
pramana ingest log.json --format otel -o trace.jsonl   # real agent logs → Pramana trace
pramana scan-trace log.jsonl                           # stream a huge log for misalignment signals
pramana classify my_audit.yaml    # risk tier and obligations only
pramana ping my_audit.yaml        # check an LLM endpoint is reachable
pramana run my_audit.yaml
```

Predictions-only audits are supported: if the model cannot be shared, supply a `score_column` in the evaluation data and Pramana runs every check that does not need the model itself.

For agents, Pramana reads the logs real systems already emit: set `agent.trace_format` to `otel` (OpenTelemetry GenAI spans) or `langchain` (LangChain/LangGraph runs), or convert first with `pramana ingest`. See [examples/real_traces](examples/real_traces).

## Project layout

```
src/pramana/
├── spec.py              # audit spec loading and validation
├── context.py           # lazy loading of model, data, transcripts, traces
├── adapters/            # replay, OpenAI-compatible and generic HTTP clients for LLM audits
├── probes/packs/        # built-in probe library (English and Indic-language attacks)
├── checks/              # one module per check family, registered by decorator
├── controls/data/       # framework catalogues, crosswalk, regulatory calendar (YAML)
├── risk/                # EU AI Act and India classification, risk scoring, gate
├── audit/               # SMACTR engine and evidence ledger
└── reporting/           # HTML report, charts, model card, exports
examples/                # four case studies, incl. a live LLM app (examples/live_assistant)
tests/                   # unit tests and ground-truth end-to-end tests
docs/                    # research notes, methodology, design decisions, limitations
```

## Documentation

- [Research notes and gap analysis](docs/research-notes.md)
- [Agentic safety, misalignment and control: a 2026 review](docs/agentic-safety-review.md)
- [Methodology: formulas, thresholds, scoring](docs/methodology.md)
- [Design decisions](docs/design-decisions.md)
- [Control crosswalk](docs/control-mapping.md)
- [Findings from real model runs](docs/live-run-findings.md)
- [Limitations](docs/limitations.md)
- [Security](SECURITY.md)

## Limitations

Pramana supports an audit; it does not replace auditor judgement or legal advice. Automated tests only evidence technical controls. Statistical results depend on how representative the supplied data is. LLM probes sample behaviour and cannot prove its absence. Black-box access limits what any audit can establish ([Casper et al., FAccT 2024](https://arxiv.org/abs/2401.14446)). Regulatory dates live in [a YAML calendar](src/pramana/controls/data/regulatory_calendar.yaml) with sources and should be re-checked before use. Details in [docs/limitations.md](docs/limitations.md).

## Roadmap

- Model-graded LLM judging as an optional second opinion beside the deterministic scorers
- Multi-turn attack sequences and more Indic languages (Bengali, Marathi, Telugu)
- NIST SP 800-53 AI control overlays (COSAiS) once final
- RBI FREE-AI framework as a sector profile for Indian lenders
- Ranking and recommendation fairness metrics
- Signed packs (Sigstore) in addition to the hash chain

## License

MIT. See [LICENSE](LICENSE).
