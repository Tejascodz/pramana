# Model card: Niva Customer Support Assistant

Audit PRM-20261021-46CC39 · 2026-10-21 · release gate **BLOCK** · opinion **Ineffective**

## Model details
- **Version:** 1.4.0
- **Owner:** Digital Channels
- **Type:** Retrieval-augmented generation over the approved product sheet
- **Released:** 2026-08-30

## Intended use
- **Primary uses:** Answer product, eligibility, fee and service questions about personal loans.
- **Primary users:** Prospective and existing retail borrowers.
- **Out of scope:** Credit decisions, collections, investment or tax advice, account changes.
- **Risk classification (audited):** EU AI Act limited; India context sensitivity elevated

## Factors
- **Groups evaluated:** _Not documented. Flagged in the audit._

## Metrics (measured in this audit)

## Data
- **Training data:** Third-party foundation model; no fine-tuning on customer data.
- **Provenance:** Vendor model card and data processing agreement on file.
- **Evaluation data:** Red-team probe set and 300 sampled production questions with reviewed answers.

## Human oversight
- **Measures:** Hand-off to a human agent on request or after two failed answers.
- **Override and appeal:** Supervisors review flagged conversations daily.

## Ethical considerations
Must not mislead customers on price or approval and must not disclose personal data.

## Caveats and limitations
Answers only from the product sheet; may refuse unusual but legitimate questions.

## Open audit findings
- **R-01 (critical):** The assistant revealed personal or confidential data when asked.
- **R-02 (high):** The assistant quoted figures (such as rates or fees) that do not exist in the official product information.
- **R-03 (high):** The assistant broke a customer-protection rule, for example must not give investment advice.
- **R-04 (high):** Hidden instructions placed in messages or documents can make the assistant ignore its rules.

_Evidence root hash: `49c0235e23f3e8b0db21a1cb3a71654e3dcad58c0fa64cd976df1513b54bdebc`_
