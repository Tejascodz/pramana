# Model card: Nilgiri Finance Personal Loan Pre-Approval Model

Audit PRM-20261021-275F46 · 2026-10-21 · release gate **BLOCK** · opinion **Ineffective**

## Model details
- **Version:** 2.3.0
- **Owner:** Credit Risk Analytics
- **Type:** Gradient-boosted decision trees (scikit-learn HistGradientBoostingClassifier)
- **Released:** 2026-09-15

## Intended use
- **Primary uses:** Automated pre-approval of unsecured personal loans up to INR 10 lakh.
- **Primary users:** Retail lending operations; underwriters for referred cases.
- **Out of scope:** _Not documented. Flagged in the audit._
- **Risk classification (audited):** EU AI Act high; India context sensitivity high

## Factors
- **Groups evaluated:** gender, age_band, residence

## Metrics (measured in this audit)
- **ROC AUC:** 0.748 (95% CI 0.731–0.765); documented claim: 0.81
- **Accuracy / F1 at threshold 0.5:** 0.773 / 0.859
- **Calibration (ECE):** 0.031
- **Disparate impact ratio, gender:** 0.97
- **Disparate impact ratio, age_band:** 0.96
- **Disparate impact ratio, residence:** 0.72
- **Top decision drivers (permutation importance):** bureau_score, pincode_risk_band, monthly_income, debt_to_income, loan_amount

## Data
- **Training data:** 8,400 historical applications from 2021 to 2024 with 12-month repayment outcomes.
- **Provenance:** Loan origination system and bureau pulls; extract prepared by Credit Risk Analytics.
- **Evaluation data:** Hold-out sample of 3,600 applications from the same period.

## Human oversight
- **Measures:** Applications below threshold are referred to an underwriter.
- **Override and appeal:** _Not documented. Flagged in the audit._

## Ethical considerations
Protected attributes are excluded from the inputs. Rural applicants may be under-represented in historical approvals.

## Caveats and limitations
Not validated for co-applicant or secured loans.

## Open audit findings
- **R-01 (high):** The documentation overstates or contradicts what the audit measured.
- **R-02 (high):** Applicants in the 'rural' group (residence) receive a favourable outcome 68% of the time versus 94% for 'urban', below the four-fifths benchmark.
- **R-03 (high):** The combined group '18-25 × rural' is treated less favourably than any single attribute reveals.
- **R-04 (high):** Some inputs (e.g. 'pincode_risk_band') closely track 'residence', so the model can discriminate indirectly even though that attribute is excluded.
- **R-05 (high):** This is a high-risk AI use under the EU AI Act, with strict duties on testing, documentation and human oversight. Its owner had classified it lower, so required controls may be missing.
- **R-06 (high):** Datasets used for modelling contain personal contact details (contact_email, mobile) that the model does not need.
- **R-07 (high):** The decision is driven mostly by bureau_score, pincode_risk_band, monthly_income; some of these drivers are not described in the documentation.
- **R-08 (medium):** Today's applicants differ from the people the model learned from (for example employment_type), although overall scores have not moved much yet.
- **R-09 (medium):** Some governance documents that were cited as evidence could not be produced.
- **R-10 (medium):** Decisions stay stable under small input changes; some business-logic expectations are violated.
- **R-11 (medium):** The model tells good and bad outcomes apart correctly about 75% of the time, which meets the bar set for this use.

_Evidence root hash: `af3fc7ef4191e270e0b54a94ddd0fb4fd411fa57968192d75a264739246f6d3d`_
