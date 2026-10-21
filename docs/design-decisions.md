# Design decisions

Short records of the main choices in Pramana and the alternatives that were rejected.

### 1. SMACTR stages as the engine structure

**Decision.** The engine runs Scoping, Mapping, Artifact collection, Testing and Reflection in order, and each stage writes evidence.
**Why.** An audit is judged on its process as much as its findings. Following a published framework (Raji et al., 2020) makes the process defensible and easy to explain to a non-technical reviewer.
**Rejected.** A flat list of tests: it produces numbers but no record of scope, failure modes or the decision that followed.

### 2. Controls and dates live in YAML, not code

**Decision.** Framework catalogues, the crosswalk and the regulatory calendar are data files.
**Why.** Regulation changes faster than code. The Digital Omnibus moved EU high-risk dates in 2026; updating Pramana for that is a one-line edit with a source URL. Governance staff can review YAML without reading Python.
**Rejected.** Hard-coded mappings, which hide the reasoning and need a release for every legal change.

### 3. A hash chain, not a signature service or blockchain

**Decision.** Append-only JSONL ledger where each entry stores the evidence hash and the previous entry's hash.
**Why.** It detects edits, deletions and reordering with only the standard library, works offline and in CI, and the root hash can be quoted in a report or e-mail. Signing the root (for example with Sigstore) is a natural next step that does not change the format.
**Rejected.** A blockchain adds infrastructure without adding assurance for a single audit pack.

### 4. Deterministic scoring for LLM probes

**Decision.** Markers, canaries, personal-data patterns, required phrases and a numeric-claim check, rather than a judge model.
**Why.** Audit evidence must be reproducible and explainable. A second model as judge introduces its own errors and version drift, and its verdicts are hard to defend. Deterministic rules are weaker on open-ended answers, so model-graded judging is on the roadmap as an optional second opinion, never the only one.

### 5. Replay mode by default

**Decision.** LLM audits read recorded responses unless a live endpoint is configured.
**Why.** In practice, auditors often receive transcripts from a test environment rather than live access. Replay makes CI runs free, fast and identical every time, and the transcript itself becomes evidence.

### 6. Permutation importance instead of SHAP

**Decision.** Use scikit-learn's model-agnostic permutation importance.
**Why.** It works for any model with `predict_proba`, adds no heavy dependency, and answers the audit question ("what drives decisions, and does that match the documentation?"). Per-decision reason codes are a model-owner responsibility, recommended in the finding.

### 7. Planted-defect case studies as tests

**Decision.** Each example plants known defects, and the end-to-end tests assert that exactly those are found. A canary check repeats this idea inside every audit.
**Why.** An audit tool that never fails a check gives false comfort. Ground truth turns "the tests pass" into "the tool detects what it claims to detect".

### 8. Honest coverage reporting

**Decision.** Controls that tests cannot evidence are shown as "not tested", not hidden or marked compliant.
**Why.** Over-claiming automated compliance is a known weakness of governance tooling. Showing the gap tells the reader exactly which policies, records and sign-offs still need to be collected, and the spec lets those documents be attached and fingerprinted.

### 9. India-specific elements are labelled as heuristics

**Decision.** The India context-sensitivity score is presented as a documented Pramana heuristic.
**Why.** The India AI Governance Guidelines are principle-based and call for an India-specific risk framework that does not yet define tiers. Presenting a heuristic as an official classification would mislead. Mapping evidence to the seven sutras, checking Indian identifiers under the DPDP Act, and screening for region-type proxies are concrete steps that do not depend on a future framework.

### 10. Exit codes as the integration contract

**Decision.** 0 success, 1 gate blocked, 2 verification failed, 3 bad input.
**Why.** A release gate has to plug into any CI system. Exit codes are the simplest contract, and the bundled GitHub Action builds on them.

### 11. No absolute paths in packs

**Decision.** The ledger stores only file names for external artifacts, and error details record only file and line.
**Why.** Audit packs are shared with reviewers and regulators. Local paths leak usernames and machine layout and make packs non-portable. A test enforces this.

### 12. The system under audit is separate from the auditor

**Decision.** The live case study ships a real application (Niva) that Pramana reaches only over HTTP, like any external endpoint.
**Why.** Auditing a raw model shows what the model does; auditing the application shows what customers experience, including retrieval, authorisation and output handling. Keeping the app outside Pramana's code means the audit cannot accidentally rely on internals, and the same spec works against any service.

### 13. Held-out probes beside the known packs

**Decision.** The live probe set includes probes the guarded build was not written against, and the report tags them.
**Why.** Guardrails tuned on a known test set pass that test set. Held-out probes measure generalisation, which is what matters for an attacker who has not read the test suite. This mirrors the train/test split auditors expect for any model.

### 14. Failed calls are evidence, and incomplete audits block

**Decision.** Adapters return errors instead of raising; checks with failed calls cannot PASS; any errored check blocks the gate as *incomplete*.
**Why.** A security test that silently skips half its probes would otherwise look like a pass. Treating "could not test" as "cannot vouch" is the conservative assurance position.

### 15. Repeated sampling with intervals, not single runs

**Decision.** `samples` repeats each probe, any failing sample fails the probe, and rates carry Wilson intervals.
**Why.** LLM outputs vary between calls, and attackers can retry. Worst-case per probe matches how an attacker benefits from retries, while the sample rate and interval show how often the failure happens.

