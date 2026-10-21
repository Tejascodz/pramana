# Limitations

Pramana supports an AI audit. It does not replace professional judgement, legal advice or a certification audit.

## Scope of evidence

- **Automated tests evidence technical controls only.** Board oversight, training, supplier management, incident handling and most of NIST GOVERN and ISO 42001 clauses 4 to 10 need organisational evidence. Pramana can fingerprint those documents but cannot judge their quality.
- **Access level limits conclusions.** Without training pipelines, weights or development records, an audit cannot rule out problems it cannot observe (Casper et al., 2024). Predictions-only audits skip robustness, importance and membership-inference tests.
- **Classification is an assessment, not legal advice.** The EU tier logic covers Art. 5, Art. 6, Annex III and Art. 50 as declared in the spec. Edge cases such as Art. 6(3) exemptions, Annex I product rules and GPAI systemic-risk thresholds need legal review.

## Statistical caveats

- Results describe the data supplied. If evaluation data is not representative of deployment, neither are the findings.
- Group metrics need adequate sample sizes. Groups under the minimum (default 30) are reported but excluded from ratios, so small groups can hide harm.
- Fairness metrics conflict. A calibrated model generally cannot also equalise error rates across groups with different base rates (Kleinberg et al., 2017). Pramana reports several metrics; choosing which one governs a decision is a policy choice for the risk owner.
- The four-fifths rule is a screening heuristic from US employment practice, not a legal standard in every jurisdiction.
- Proxy screening measures association, not causation. A flagged feature may be legitimate if it is justified and its effect is tested.
- The membership-inference test is a simple loss-threshold attack. Stronger attacks can succeed where it fails.

## LLM and agent testing

- Probe sets are samples. Passing every probe does not prove safety; failing one proves a problem exists.
- Deterministic scoring can miss paraphrased leaks or harmful content that avoids the configured markers, and can flag harmless numbers that are not in the knowledge base.
- Replay mode audits the recorded behaviour, not the current deployment. Live mode depends on the endpoint behaving the same way in production.
- Agent checks assume the log is complete. An agent that acts outside its logging pipeline cannot be audited from its logs; this is why tamper-evidence and gateway-enforced logging are recommended.

## Data and dates

- The regulatory calendar was last reviewed on the date in `regulatory_calendar.yaml`. Dates in the EU AI Act changed in 2026 and may change again. Check sources before relying on them.
- Framework catalogues list control identifiers with short paraphrased titles. The official texts are authoritative; ISO standards must be obtained from ISO.
- The case-study data is synthetic. Defects were planted to demonstrate detection and do not describe any real organisation.

## Security

Model files in pickle or joblib format can run code when loaded. Only audit models received through a trusted, access-controlled channel, or use a predictions-only audit.
