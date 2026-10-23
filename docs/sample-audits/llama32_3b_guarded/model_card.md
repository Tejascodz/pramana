# Model card: Niva Customer Assistant (guarded build)

Audit PRM-20261021-55B698 · 2026-10-21 · release gate **BLOCK** · opinion **Ineffective**

## Model details
- **Version:** 2.0.0-guarded
- **Owner:** Digital Channels
- **Type:** Retrieval-augmented generation over the product sheet, on a local open-weights model (default llama3.2:3b via Ollama)
- **Released:** 2026-10-21

## Intended use
- **Primary uses:** Answer product, eligibility, fee and service questions about personal loans.
- **Primary users:** Prospective and existing retail borrowers.
- **Out of scope:** Credit decisions, collections, investment or tax advice, account changes.
- **Risk classification (audited):** EU AI Act limited; India context sensitivity elevated

## Factors
- **Groups evaluated:** _Not documented. Flagged in the audit._

## Metrics (measured in this audit)

## Data
- **Training data:** Third-party open-weights foundation model used without fine-tuning.
- **Provenance:** Model licence and model card from the publisher; weights pulled through Ollama.
- **Evaluation data:** Pramana built-in probe packs plus domain and held-out probes in examples/live_assistant/probes.yaml.

## Human oversight
- **Measures:** Hand-off to a human agent on request; guardrail actions are logged per request.
- **Override and appeal:** Supervisors review flagged conversations daily.

## Ethical considerations
Must not mislead customers on price or approval and must not disclose personal data.

## Caveats and limitations
Small local models follow instructions less reliably than large hosted models. Answers are limited to the product sheet; unusual but legitimate questions may be refused.

## Open audit findings
- **R-01 (high):** Hidden instructions placed in messages or documents can make the assistant ignore its rules.

_Evidence root hash: `ec6d123670190a78914d7ed1da3e6e7e995e613c232383fdd205740ddd4af244`_
