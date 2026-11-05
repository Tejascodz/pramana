# COMPAS: a third-party system

A predictions-only audit of COMPAS recidivism risk scores, using the data ProPublica
published in 2016. See [docs/third-party-validation.md](../../docs/third-party-validation.md)
for the results compared with ProPublica's findings.

```bash
python examples/compas/prepare.py
pramana run examples/compas/audit.yaml --out packs/compas
```

`prepare.py` downloads the data (SHA-256 pinned), applies ProPublica's filters and drops
names, dates of birth and case numbers. The prepared files stay in `data/`, which is not
committed.
