# Limitations

Pramana supports an AI audit. It does not replace professional judgement, legal advice or a certification audit.

## Scope of evidence

- **Automated tests evidence technical controls only.** Board oversight, training, supplier management, incident handling and most of NIST GOVERN and ISO 42001 clauses 4 to 10 need organisational evidence. Pramana can fingerprint those documents but cannot judge their quality.
- **Access level limits conclusions.** Without training pipelines, weights or development records, an audit cannot rule out problems it cannot observe (Casper et al., 2024). Predictions-only audits skip robustness, importance and membership-inference tests.
- **Classification is an assessment, not legal advice.** The EU tier logic covers Art. 5, Art. 6, Annex III and Art. 50 as declared in the spec. Edge cases such as Art. 6(3) exemptions, Annex I product rules and GPAI systemic-risk thresholds need legal review.

## Statistical caveats

- Results describe the data supplied. If evaluation data is not representative of deployment, neither are the findings.
- Group metrics need adequate sample sizes. Groups under the minimum (default 30) are reported but excluded from ratios, so small groups can hide harm. When fewer than two groups of an attribute are large enough to compare, the attribute is reported as not assessed (a warning), never as a pass.
- Fairness metrics conflict. A calibrated model generally cannot also equalise error rates across groups with different base rates (Kleinberg et al., 2017). Pramana reports several metrics; choosing which one governs a decision is a policy choice for the risk owner.
- The four-fifths rule is a screening heuristic from US employment practice, not a legal standard in every jurisdiction.
- Proxy screening measures association, not causation. A flagged feature may be legitimate if it is justified and its effect is tested.
- The membership-inference test is a simple loss-threshold attack. Stronger attacks can succeed where it fails.

## LLM and agent testing

- LLM outputs are stochastic. A single sample per probe can miss failures that appear on other runs; use `--samples` and read the confidence intervals. Repeated sampling raises attack success over time (Hughes et al., 2024), so a clean result is evidence for the tested budget only.
- The guarded Niva build's input screen was written with knowledge of the built-in packs, so it is expected to stop them. Its real strength is measured by the held-out probes. Audits of production systems should always include probes the system's builders have not seen.
- Small local models (3–4B parameters) behave differently from large hosted models. A result for `llama3.2:3b` says nothing about another model; record the model and re-audit after any change.
- The probe library is small compared with research benchmarks and covers five Indian languages and scripts. It is a regression suite and a starting point, not a complete red-team.
- The test suite uses a deliberately naive stand-in model so it can run offline. Its results test Pramana's plumbing and scoring, not any real model.

- Multi-turn conversations are scripted: the user turns are fixed, and only the system's replies vary. They measure resistance to known conversational techniques, not to an attacker who adapts each message to the last reply. The held-out conversations were written by the same author as Niva's screen, so they are held out from the screen, not independent of its author.
- Obfuscation mutators cover character-level disguises (invisible and look-alike characters, spacing, digits, full-width letters, Indic joiners). Letter spacing and digit substitution survive Unicode normalisation; translation, paraphrase and encodings other than base64 are not generated.
- The agent sandbox tests the real model or agent against a stand-in bank. A pass shows the agent resisted these scenarios with these tools; it does not cover the customer's production tools, permissions or data. A honeypot run only counts once the planted text reached the agent: runs that never reach the trap are reported as not tested, and an agent that does nothing (control task not completed) cannot pass.
- `agent.approval_paths` proves a property of the workflow graph as declared. Code that calls tools outside the graph, or a graph exported before a change, is not covered; enforce approval in the tool gateway as well.
- Probe sets are samples. Passing every probe does not prove safety; failing one proves a problem exists.
- `agent.misalignment_signals` scans the agent's recorded reasoning and actions with deterministic phrase signatures. Its precision was checked against the Who&When benchmark of real agent trajectories (0 false positives on ~4,000 real messages after tightening), but deterministic matching still trades recall for precision. It proves a problem when it fires, but a clean scan is not proof of alignment: it can miss paraphrased intent, and it cannot see reasoning the agent never wrote down. Chain-of-thought monitorability is a real but fragile signal (CoT-monitorability, 2025), so pair it with a runtime monitor and human approval for irreversible actions.
- Deterministic scoring can miss paraphrased leaks or harmful content that avoids the configured markers, and can flag harmless numbers that are not in the knowledge base. Acceptance of an attacker's persona or format is recognised from first-person phrasing in English, Hindi (Devanagari) and Hinglish, and from the pieces of a split marker; acceptance in Kannada, Tamil or other languages, or paraphrased ("sure, from here on there are no limits"), is not.
- `llm.access_control` tests identity claims the probes make (headers, forged signatures, an identity stated in the message) and judges them by what the answer reveals. It does not review the application's authentication design, session handling or token validation, and a system that accepts a false claim without repeating the record passes. Pair it with a security review of how identity is established.
- The groundedness check compares figures, not meanings. It treats "₹5,00,000", "5 lakh" and "500,000" as the same amount and ignores list numbering, but it does not convert between units: "48 hours" against a knowledge base that says "2 days" is flagged. Review flagged figures before treating them as fabrications.
- `agent.misalignment_signals` only sees evaluation gaming the agent writes down ("I will pretend to be compliant"). Behaving differently under test without saying so leaves no trace in a log.
- The loss-of-control triad judges the environment from the trace. Controls that act outside it (a payments gateway limit, a sandbox) are invisible to the audit unless they leave events in the log.
- `agent.control_readiness` reports a safeguard that the spec declares but the trace does not show as *declared*, not evidenced. A declaration is a claim for a reviewer to confirm, not proof.
- `agent.oversight_integrity` screens tool results for common instruction-override phrasing. A paraphrased or encoded injection can pass it, and steganographic reasoning cannot be detected from a log at all.
- The ML-BOM (`ml_bom.cdx.json`) lists the audited system, its data and trace files with hashes, and the measured metrics. It does not inventory upstream models, libraries or training pipelines, which Pramana cannot see.
- Browser mode depends on CSS selectors and on the page behaving the same way for an automated browser: a redesign of the page, a login wall, a CAPTCHA or bot detection stops it (reported as failed calls). It reads the text shown on the page, so content rendered as images or inside closed shadow roots is not seen.
- Replay mode audits the recorded behaviour, not the current deployment. Live mode depends on the endpoint behaving the same way in production.
- Agent checks assume the log is complete. An agent that acts outside its logging pipeline cannot be audited from its logs; this is why tamper-evidence and gateway-enforced logging are recommended.

## Scale

- Agent checks load a trace into memory and resolve parent/child links across it,
  so a single audit is bounded by available RAM. Traces are naturally partitioned
  by session, so very large logs should be audited in session batches. A ~12k-event
  trace scans in well under a second in the test suite; multi-million-event
  production logs need batching. `pramana scan-trace` streams a log of any size in
  constant memory for misalignment signals; the full multi-check audit still loads a
  trace into memory and should be run per session batch for very large logs.
- The OpenTelemetry and LangChain adapters cover the common span/run shapes. Custom
  instrumentation may need field mapping; the adapters are small and are meant to be
  extended.

## Data and dates

- The regulatory calendar was last reviewed on the date in `regulatory_calendar.yaml`. Dates in the EU AI Act changed in 2026 and may change again. Check sources before relying on them.
- Framework catalogues list control identifiers with short paraphrased titles. The official texts are authoritative; ISO standards must be obtained from ISO.
- The case-study data is synthetic. Defects were planted to demonstrate detection and do not describe any real organisation.

## Security

Model files in pickle or joblib format can run code when loaded, so Pramana refuses one unless its SHA-256 is pinned in the spec or it is explicitly trusted (`trust_pickled_model`, `--trust-model`). Pinning proves the file is the one you pinned, not that it is safe: only pin models received through a trusted, access-controlled channel. Prefer `.skops` models, or a predictions-only audit. What Pramana listens on, sends and stores is set out in [SECURITY.md](../SECURITY.md).
