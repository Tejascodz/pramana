"""Labelled benchmarks that measure Pramana's own scoring, and any judge model, on the same data.

``injection_labelled.yaml`` holds attack/reply pairs labelled by hand as *complied* or
*resisted*, chosen to be hard in both directions (leaks that avoid the exact proof;
refusals that quote the attack). ``run()`` scores them with Pramana's deterministic
rules and, if given, a judge model and the hybrid of the two, and reports precision
and recall (positive class: complied) with 95% Wilson intervals, per kind of case.

    pramana benchmark                       # the rules alone
    pramana benchmark --judge-url http://127.0.0.1:11434/v1 --judge-model qwen2.5:7b

The labels are the author's judgement and are published for checking.
"""

from __future__ import annotations

from importlib import resources
from typing import Any

from pramana.metrics import wilson_interval
from pramana.safeio import parse_yaml


def load_cases() -> tuple[str, list[dict[str, Any]]]:
    canary, cases, _ = load_benchmark()
    return canary, cases


def load_benchmark() -> tuple[str, list[dict[str, Any]], str]:
    """(canary, cases, the assistant's system prompt) with the canary filled in."""
    text = (
        resources.files("pramana.benchmarks")
        .joinpath("injection_labelled.yaml")
        .read_text(encoding="utf-8")
    )
    data = parse_yaml(text)
    canary = str(data["canary"])
    cases = []
    for case in data["cases"]:
        filled = dict(case)
        filled["success_markers"] = [
            m.replace("{canary}", canary) for m in case.get("success_markers", [])
        ]
        cases.append(filled)
    return canary, cases, str(data.get("system_prompt", "")).replace("{canary}", canary)


def rule_verdict(case: dict[str, Any], canary: str) -> bool:
    """Pramana's deterministic verdict for one case: did the reply prove the attack worked?"""
    from pramana.checks.llm import injection_verdict

    probe = {
        "prompt": case["attack"],
        "success_markers": case.get("success_markers", []),
        "success_regex": case.get("success_regex", []),
    }
    return injection_verdict(case["response"], probe, canary)[0]


def confusion(labels: list[bool], predicted: list[bool]) -> dict[str, Any]:
    """Precision and recall for the positive class (complied), with 95% Wilson intervals."""
    tp = sum(1 for y, p in zip(labels, predicted, strict=True) if y and p)
    fp = sum(1 for y, p in zip(labels, predicted, strict=True) if not y and p)
    fn = sum(1 for y, p in zip(labels, predicted, strict=True) if y and not p)
    tn = sum(1 for y, p in zip(labels, predicted, strict=True) if not y and not p)

    def rate(k: int, n: int) -> dict[str, Any]:
        if not n:
            return {"value": None, "ci": [None, None], "of": 0}
        lo, hi = wilson_interval(k, n)
        return {"value": round(k / n, 4), "ci": [round(lo, 4), round(hi, 4)], "of": n}

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": rate(tp, tp + fp),
        "recall": rate(tp, tp + fn),
        "accuracy": rate(tp + tn, len(labels)),
    }  # fmt: skip


def run(judge: Any = None, instructions: bool = True) -> dict[str, Any]:
    """Score every case with the rules (and the judge and the hybrid, if a judge is given).

    With ``instructions`` the judge is shown the assistant's system prompt, as it is in an
    audit that knows it; without, it sees only the attack and the reply.
    """
    canary, cases, system_prompt = load_benchmark()
    labels = [c["label"] == "complied" for c in cases]
    rules = [rule_verdict(c, canary) for c in cases]
    rows = [
        {"id": c["id"], "kind": c["kind"], "label": c["label"], "rules": r}
        for c, r in zip(cases, rules, strict=True)
    ]
    report: dict[str, Any] = {
        "benchmark": "injection_labelled",
        "cases": len(cases),
        "complied_cases": sum(labels),
        "rules": confusion(labels, rules),
    }
    if judge is not None:
        shown = system_prompt if instructions else ""
        verdicts = judge.verdicts([(c["attack"], c["response"], shown) for c in cases])
        flagged = [v["verdict"] == "complied" for v in verdicts]
        hybrid = [r or f for r, f in zip(rules, flagged, strict=True)]
        for row, v in zip(rows, verdicts, strict=True):
            row["judge"] = v["verdict"]
        report["judge_model"] = judge.label
        report["judge_saw_instructions"] = bool(shown)
        report["judge"] = confusion(labels, flagged)
        report["judge_unclear"] = sum(1 for v in verdicts if v["verdict"] == "unclear")
        report["judge_errors"] = sum(1 for v in verdicts if v.get("error"))
        report["hybrid"] = confusion(labels, hybrid)
    by_kind: dict[str, dict[str, int]] = {}
    for row in rows:
        stat = by_kind.setdefault(
            row["kind"], {"cases": 0, "label": row["label"], "rules_right": 0}
        )
        stat["cases"] += 1
        stat["rules_right"] += int(row["rules"] == (row["label"] == "complied"))
        if "judge" in row:
            stat.setdefault("judge_right", 0)
            stat["judge_right"] += int((row["judge"] == "complied") == (row["label"] == "complied"))
    report["by_kind"] = by_kind
    report["rows"] = rows
    return report
