# Validating on real agent trajectories (Who&When)

Pramana's case studies use synthetic data with planted defects, which proves the
checks fire on a known answer. This example does the complementary thing: it runs
the misalignment detector over **real, independently collected multi-agent
trajectories** from the [Who&When benchmark](https://github.com/ag2ai/Agents_Failure_Attribution)
(ICML 2025 Spotlight, MIT) to measure its **precision** — does it stay quiet on
real logs where there is no misalignment?

`sample/` holds three unmodified Who&When trajectories (see `NOTICE` for
attribution). Convert and scan them:

```bash
python examples/benchmark_whowhen/convert_whowhen.py examples/benchmark_whowhen/sample ww.jsonl
pramana scan-trace ww.jsonl
```

## What this found, and why it mattered

Run against the full Who&When set (184 trajectories, ~4,000 agent messages), the
first version of the detector raised **19 signals — nearly all false positives**:
the word "hide" scraped from web-page menus ("Contents hide"), a company name
("Diversified Metal Fabricators"), and a trivia answer ("conceal themselves with
a parachute"). None were misalignment.

That is exactly what real data is for. The detector was tightened: the polysemous
patterns now require the agent to be stating its **own first-person intent**, and
hide/conceal/privilege patterns require a concrete object. After the fix the same
4,000 messages produced **0 false positives**, while every planted and real rogue
example still fires. The fix, and its before/after, are recorded in
[docs/agentic-safety-review.md](../../docs/agentic-safety-review.md).

Auditing the auditor against real data — and fixing what it got wrong — is the
method, not an afterthought.
