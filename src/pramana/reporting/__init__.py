"""Report generation: HTML report, model card, machine-readable exports."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from pramana import NOTICE, __version__, safefs
from pramana.audit.ledger import EvidenceLedger
from pramana.checks.llm import fmt_ms
from pramana.controls import load_library
from pramana.reporting.charts import coverage_bars, group_bars, risk_heatmap
from pramana.reporting.ml_bom import render_ml_bom
from pramana.reporting.model_card import render_model_card
from pramana.reporting.narrative import executive_summary
from pramana.safeio import csv_safe, strict_json
from pramana.types import Status

REPORT_FILES = {
    "report": "report.html",
    "results": "results.json",
    "risk_register": "risk_register.csv",
    "control_coverage": "control_coverage.csv",
    "remediation_plan": "remediation_plan.csv",
    "model_card": "model_card.md",
    "ml_bom": "ml_bom.cdx.json",
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
        notice=NOTICE,
    )


def _csv_text(rows: list[dict[str, Any]], fields: list[str]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                k: csv_safe("; ".join(map(str, v)) if isinstance(v, list) else v)
                for k, v in row.items()
            }
        )
    return buffer.getvalue()


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    safefs.write_user_file(path, _csv_text(rows, fields))


def render_outputs(result) -> dict[str, str]:
    """Every report file's content, keyed like ``REPORT_FILES``, built in memory."""
    return {
        "report": render_html(result),
        "results": json.dumps(
            strict_json(result.to_dict()), indent=2, default=str, allow_nan=False
        ),
        "risk_register": _csv_text(
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
        ),
        "control_coverage": _csv_text(
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
        ),
        "remediation_plan": _csv_text(
            result.remediation,
            ["risk_id", "priority", "action", "owner", "due", "closes_controls"],
        ),
        "model_card": render_model_card(result),
        "ml_bom": json.dumps(render_ml_bom(result), indent=2, ensure_ascii=False) + "\n",
    }


def write_outputs(result, out_dir: Path, ledger: EvidenceLedger | None = None) -> dict[str, Path]:
    """Write the report pack. If a ledger is given, report files are sealed into it.

    Every file is rendered in memory and every destination checked before anything is
    written, so a rendering error or a prepared folder (a link, or a folder where a file
    belongs) leaves the existing files untouched. Each file is then written to a
    temporary file and renamed into place: a link at the destination is refused, and a
    hard link is replaced, never written through.
    """
    out = Path(out_dir)
    contents = render_outputs(result)
    with safefs.open_dir(out) as folder:
        for name in REPORT_FILES.values():
            safefs.check_replaceable(folder, name)
        for key, name in REPORT_FILES.items():
            safefs.replace_file(folder, name, contents[key].encode("utf-8"))
    paths = {key: out / name for key, name in REPORT_FILES.items()}
    if ledger is not None:
        for key, path in paths.items():
            ledger.add_pack_file("6-reporting", key, path.name)
    return paths
