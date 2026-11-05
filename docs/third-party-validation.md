# Third-party validation: COMPAS

Every other example in this repository audits a system its authors built. This one
does not. COMPAS is a commercial recidivism risk score used by courts in the United
States. ProPublica obtained the scores given to defendants in Broward County, Florida,
in 2013 and 2014, matched them with criminal records over the next two years, and
published both the data and its findings ("Machine Bias", 2016,
[github.com/propublica/compas-analysis](https://github.com/propublica/compas-analysis)).
That makes it a fair test: a real deployed system, real outcomes, and published
numbers to check Pramana against.

```bash
python examples/compas/prepare.py      # downloads the data, checks its SHA-256, drops names
pramana run examples/compas/audit.yaml --out packs/compas
```

The data holds names and dates of birth of real people, so it is not copied into this
repository. `prepare.py` downloads it, refuses it if the hash differs, applies
ProPublica's own filters (6,172 defendants) and keeps only the columns the audit needs.
The audit is predictions-only: Pramana sees the scores and outcomes, not the model.
A decile of 1 to 4 counts as a low-risk (favourable) decision, as in ProPublica's
analysis. CI repeats this on every push.

## Does Pramana find what ProPublica found?

| | Pramana | ProPublica |
|---|---|---|
| Defendants analysed | 6,172 | 6,172 |
| Black defendants labelled higher risk who did not reoffend | 42.3% | 44.9% |
| White defendants labelled higher risk who did not reoffend | 22.0% | 23.5% |
| White defendants labelled lower risk who did reoffend | 49.6% | 47.7% |
| Black defendants labelled lower risk who did reoffend | 28.5% | 28.0% |

Pramana reaches the same finding without being told what to look for: the error rates
differ sharply by race, in the direction ProPublica reported. The gaps of 0.5 to 2.6
points are expected: ProPublica's error-rate table was computed from a different file in
its repository (`cox-parsed.csv`, with its own recidivism window), not the two-year file
used here. The test in CI allows 3 points.

The rest of the audit:

- **Fairness: fail, critical.** Disparate impact 0.53 by race and 0.46 by age group; the
  equalized-odds difference by race is 0.38. Pramana also reports that the groups'
  reoffending rates differ by 0.27, so equal error rates and calibration cannot both
  hold (Kleinberg et al., 2017): which one should govern is a policy decision, which is
  the core of the published dispute between ProPublica and Northpointe.
- **Discrimination: warn.** AUC 0.710 (95% CI 0.699 to 0.722), accuracy 66.1%, in line
  with published re-analyses (around 0.70 AUC and 65% accuracy).
- **Calibration: fail.** Decile scores are ranks, not probabilities; read as
  probabilities they are off by 13 points on average.
- **Proxy features: fail.** The type of charge predicts race with AUC 0.72.
- **Drift 2013 to 2014: pass.** Release gate: **BLOCK**.

## What it found wrong with Pramana

Three problems that none of the in-house examples had triggered, each now fixed with a
test:

1. **Membership inference ran on data that was not training data.** It assumed the
   reference data (here, 2013) was the model's training set, which in a predictions-only
   audit it usually is not. It now runs only when the model is audited or the spec sets
   `reference_is_training: true`. With only ten distinct scores, ties had also inflated
   its "true-positive rate at 1% false-positive rate"; that figure is now computed at a
   rate the attack actually achieves, or reported as not measurable.
2. **Different people were counted as duplicate records.** Duplicates were judged on the
   model's few, coarse features, so 64.8% of defendants looked like duplicates. Rows are
   now compared in full, and without a record identifier identical rows are noted (they
   may be different people with the same values), not graded.
3. **An India rating appeared for a US-only system.** It is now labelled a benchmark when
   India is not a declared deployment region.

## Limits of this validation

One dataset, one kind of system (a tabular risk score), predictions only. It shows the
fairness, performance, calibration and drift arithmetic agrees with an independent,
published analysis on real data. It says nothing about the LLM or agent checks, which
still need runs against applications and agents built by others.
