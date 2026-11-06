# Credit scoring case study

A gradient-boosted loan pre-approval model for Nilgiri Finance, a fictional Indian
lender. Every record is synthetic. Defects are planted on purpose, so the audit can
be checked against a known answer; `tests/test_end_to_end.py` fails if Pramana misses
one or flags a clean area.

## Run it

```bash
pip install -e ".[dev]"                                   # from the repository root
python examples/credit_scoring/build_model.py             # writes data/*.csv and model.joblib
pramana run examples/credit_scoring/audit.yaml --out packs/credit
pramana verify packs/credit
```

`build_model.py` needs only Pramana's own dependencies (NumPy, pandas, scikit-learn,
joblib). It uses a fixed seed, so every run produces the same data and model. The model is
a pickle written on your own computer, which is why `audit.yaml` sets
`trust_pickled_model: true`; for a model someone else gives you, pin its SHA-256 under
`artifacts_sha256` instead.

## What is planted, and what Pramana should report

| Planted defect | Check | Expected result |
|---|---|---|
| Historical labels biased against rural applicants, worst for rural women | `fairness.group_parity`, `fairness.intersectional` | FAIL: disparate impact 0.72 for rural vs urban; 0.66 for the worst age × residence pair |
| `pincode_risk_band` tracks residence | `fairness.proxy_features` | FAIL: pincode predicts residence with AUC 0.99 |
| E-mail and mobile columns left in the extracts | `privacy.pii_exposure` | FAIL |
| Model card overstates AUC and leaves sections empty | `documentation.model_card` | FAIL: claims that do not match the measured AUC |
| Owner classed the system as "limited" risk | `governance.risk_classification` | FAIL: credit scoring is high-risk under Annex III 5(b) |
| Income and gig-work share drift in production | `drift.population_stability` | WARN |
| Missing bureau scores and 60 duplicate rows | `data_quality.integrity` | WARN |
| Fundamental-rights impact assessment cited but not supplied | `governance.manual_evidence` | WARN: the file under `governance/` is missing on purpose |

Calibration, membership inference and the audit's self-test should pass. The release
gate is **BLOCK**. The published pack for this case is in
[docs/sample-audits/credit_scoring](../../docs/sample-audits/credit_scoring).
