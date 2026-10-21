# Contributing

Thanks for your interest in Pramana.

## Set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,dashboard]"
make test lint
```

## Adding a check

1. Create or extend a module in `src/pramana/checks/` and register the function with `@register(...)`.
2. Return a `CheckResult` with a technical `summary`, a one-sentence `plain_summary` for executives, and a `recommendation`.
3. Raise `MissingArtifact` when an input the check needs was not supplied; the engine records it as skipped.
4. Add the check to `src/pramana/controls/data/crosswalk.yaml` with its failure mode, effect and controls. `tests/test_controls.py` fails if you forget.
5. Add unit tests, and if possible plant the defect in a case study so the end-to-end tests cover it.
6. Document the formula and threshold in `docs/methodology.md`.

## Adding probes

Add probes to a pack in `src/pramana/probes/packs/` (shipped with the package) or to a probe file next to your audit spec. Every probe needs a unique `id` and a `prompt`. For injection probes, prove compliance with `success_markers` (split the marker across the prompt so quoting it back does not count), `success_regex`, or `{canary}`. Tag probes with `technique`, `language` and `owasp` so results can be grouped. Add a held-out probe for every new guardrail you test.

## Updating regulation

Edit `src/pramana/controls/data/regulatory_calendar.yaml` or the framework catalogues. Every milestone needs a source URL; update `last_reviewed`. Regenerate the crosswalk doc with `make docs`.

## Style

Ruff handles linting and formatting (`ruff check` and `ruff format`). Keep reports and plain summaries in plain language.
