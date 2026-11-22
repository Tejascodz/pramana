# Model card: COMPAS recidivism risk scores (Broward County, Florida)

Audit PRM-20261021-F24CBA · 2026-10-21 · release gate **BLOCK** · opinion **Ineffective**

## Model details
- **Version:** 2013-2014
- **Owner:** Northpointe (now equivant); scores as published by ProPublica
- **Type:** _Not documented. Flagged in the audit._
- **Released:** _Not documented. Flagged in the audit._

## Intended use
- **Primary uses:** Assess the risk that a defendant will reoffend, to inform pre-trial decisions.
- **Primary users:** _Not documented. Flagged in the audit._
- **Out of scope:** _Not documented. Flagged in the audit._
- **Risk classification (audited):** EU AI Act high; India context sensitivity high

## Factors
- **Groups evaluated:** race, sex, age_cat

## Metrics (measured in this audit)
- **ROC AUC:** 0.710 (95% CI 0.699–0.722); documented claim: _Not documented. Flagged in the audit._
- **Accuracy / F1 at threshold 0.65:** 0.661 / 0.691
- **Calibration (ECE):** 0.134
- **Disparate impact ratio, race:** 0.53
- **Disparate impact ratio, sex:** 0.92
- **Disparate impact ratio, age_cat:** 0.46

## Data
- **Training data:** _Not documented. Flagged in the audit._
- **Provenance:** _Not documented. Flagged in the audit._
- **Evaluation data:** _Not documented. Flagged in the audit._

## Human oversight
- **Measures:** _Not documented. Flagged in the audit._
- **Override and appeal:** _Not documented. Flagged in the audit._

## Ethical considerations
_Not documented. Flagged in the audit._

## Caveats and limitations
_Not documented. Flagged in the audit._

## Open audit findings
- **R-01 (critical):** Applicants in the 'Less than 25' group (age_cat) receive a favourable outcome 36% of the time versus 78% for 'Greater than 45', below the four-fifths benchmark.
- **R-02 (critical):** The combined group 'African-American × Less than 25' is treated less favourably than any single attribute reveals.
- **R-03 (high):** Some inputs (e.g. 'age') closely track 'age_cat', so the model can discriminate indirectly even though that attribute is excluded.
- **R-04 (high):** Risk scores do not match observed outcome rates closely enough to be read as probabilities.
- **R-05 (medium):** The model tells good and bad outcomes apart correctly about 71% of the time, which meets the bar set for this use.
- **R-06 (medium):** This is a high-risk AI use under the EU AI Act, with strict duties on testing, documentation and human oversight.

_Evidence root hash: `85db8370997027ad8c414f871441e7bb0179a8fb033ba916b3ef3971920e53a6`_

_Automated test evidence for a qualified reviewer, not a certification, legal opinion or regulatory approval. A pass covers only the checks that ran, on the inputs and samples recorded in this pack. See https://github.com/Tejascodz/pramana/blob/main/DISCLAIMER.md_
