"""Report generation: HTML report, model card, machine-readable exports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from pramana import __version__
from pramana.audit.ledger import EvidenceLedger
from pramana.checks.llm import fmt_ms
from pramana.controls import load_library
from pramana.reporting.charts import coverage_bars, group_bars, risk_heatmap
from pramana.reporting.model_card import render_model_card
from pramana.reporting.narrative import executive_summary
from pramana.types import Status

REPORT_FILES = {
    "report": "report.html",
    "results": "results.json",
    "risk_register": "risk_register.csv",
    "control_coverage": "control_coverage.csv",
    "remediation_plan": "remediation_plan.csv",
    "model_card": "model_card.md",
}


def _fairness_view(result) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    parity = result.result("fairness.group_parity")
    if not parity or parity.status in (Status.SKIPPED, Status.ERROR):
        return None, None
    attrs = parity.details.get("attributes", {})
    ranked = [
        (a, v) for a, v in attrs.items() if v["summary"].get("disparate_impact_ratio") is not None
    ]
    if not ranked:
        return None, None
    attr, view = min(ranked, key=lambda kv: kv[1]["summary"]["disparate_impact_ratio"])
    fairness = {
        "attribute": attr,
        "groups": view["groups"],
        "chart": group_bars(view["groups"], f"Favourable rate by {attr}"),
    }
    inter = result.result("fairness.intersectional")
    intersectional = None
    if (
        inter
        and inter.status not in (Status.SKIPPED, Status.ERROR)
        and inter.metrics.get("worst_pair")
    ):
        pair = inter.metrics["worst_pair"]
        groups = sorted(inter.details["pairs"][pair]["groups"], key=lambda g: g["selection_rate"])
        intersectional = {"pair": pair, "groups": groups}
    return fairness, intersectional


def render_html(result) -> str:
    env = Environment(
        loader=PackageLoader("pramana", "reporting/templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["ms"] = fmt_ms
    template = env.get_template("report.html.j2")
    counts = Counter(r.status.value for r in result.results)
    executed = sum(1 for r in result.results if r.status not in (Status.SKIPPED,))
    open_by_rating = Counter(r.rating.value for r in result.risks if not r.accepted)
    applicable = [c for c in result.coverage["controls"] if c["state"] != "not applicable"]
    evidenced = sum(1 for c in applicable if c["state"] == "evidenced")
    fairness, intersectional = _fairness_view(result)
    frameworks_shown = sum(
        1
        for fw in result.coverage["frameworks"].values()
        if any(fw["totals"][s] for s in ("evidenced", "partial", "deficient", "not tested"))
    )
    return template.render(
        r=result,
        s=executive_summary(result),
        counts=counts,
        executed=executed,
        findings_count=sum(1 for r in result.results if r.status.is_finding),
        open_by_rating={
            k: open_by_rating.get(k, 0) for k in ("critical", "high", "medium", "low", "info")
        },
        coverage_pct=round(100 * evidenced / len(applicable)) if applicable else 0,
        tested_controls=sum(
            1 for c in applicable if c["state"] in ("evidenced", "partial", "deficient")
        ),
        applicable_controls=len(applicable),
        heatmap=risk_heatmap([r.to_dict() for r in result.risks]),
        coverage_chart=coverage_bars(result.coverage["frameworks"]),
        fairness=fairness,
        intersectional=intersectional,
        min_group=int(result.spec.threshold("min_group_size")),
        frameworks_shown=frameworks_shown,
        multi_sample=int(result.llm_run.get("samples_per_probe") or 1) > 1,
        calendar_reviewed=load_library().calendar.get("last_reviewed"),
        version=__version__,
    )


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: "; ".join(v) if isinstance(v, list) else v for k, v in row.items()})


def write_outputs(result, out_dir: Path, ledger: EvidenceLedger | None = None) -> dict[str, Path]:
    """Write the report pack. If a ledger is given, report files are sealed into it."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {key: out / name for key, name in REPORT_FILES.items()}

    paths["report"].write_text(render_html(result), encoding="utf-8")
    paths["results"].write_text(
        json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8"
    )
    _write_csv(
        paths["risk_register"],
        [r.to_dict() for r in result.risks],
        [
            "risk_id",
            "title",
            "source_check",
            "likelihood",
            "impact",
            "score",
            "rating",
            "owner",
            "treatment",
            "description",
            "recommendation",
            "controls",
        ],
    )
    _write_csv(
        paths["control_coverage"],
        result.coverage["controls"],
        [
            "framework",
            "id",
            "group",
            "title",
            "evidence_type",
            "state",
            "checks",
            "manual_evidence",
        ],
    )
    _write_csv(
        paths["remediation_plan"],
        result.remediation,
        ["risk_id", "priority", "action", "owner", "due", "closes_controls"],
    )
    paths["model_card"].write_text(render_model_card(result), encoding="utf-8")

    if ledger is not None:
        for key, path in paths.items():
            ledger.add_pack_file("6-reporting", key, path.name)
    return paths
