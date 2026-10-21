"""Model card in Markdown (Mitchell et al., 2019), filled with audited evidence.

Owner-supplied text is kept as written. Measured results come from this audit,
and fields the owner left empty are marked so the gap stays visible.
"""

from __future__ import annotations

from typing import Any

from pramana.types import Status

GAP = "_Not documented. Flagged in the audit._"


def _get(doc: dict[str, Any], dotted: str) -> Any:
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _text(value: Any) -> str:
    if value is None or (
        isinstance(value, str) and (not value.strip() or value.strip().upper() in {"TBD", "TODO"})
    ):
        return GAP
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else GAP
    return str(value).strip()


def render_model_card(result) -> str:
    spec = result.spec
    doc = (spec.artifact("documentation") and _load(spec)) or {}
    perf = result.result("performance.discrimination")
    cal = result.result("calibration.reliability")
    parity = result.result("fairness.group_parity")
    drivers = result.result("explainability.feature_importance")

    lines = [
        f"# Model card: {spec.name}",
        "",
        f"Audit {result.audit_id} · {result.audit_date.isoformat()} · release gate **{result.gate['decision']}** · "
        f"opinion **{result.opinion['rating']}**",
        "",
        "## Model details",
        f"- **Version:** {spec.system['version']}",
        f"- **Owner:** {_text(_get(doc, 'model_details.owner') or spec.system.get('owner'))}",
        f"- **Type:** {_text(_get(doc, 'model_details.type'))}",
        f"- **Released:** {_text(_get(doc, 'model_details.date'))}",
        "",
        "## Intended use",
        f"- **Primary uses:** {_text(_get(doc, 'intended_use.primary_uses') or spec.use_case.get('purpose'))}",
        f"- **Primary users:** {_text(_get(doc, 'intended_use.primary_users'))}",
        f"- **Out of scope:** {_text(_get(doc, 'intended_use.out_of_scope_uses'))}",
        f"- **Risk classification (audited):** EU AI Act {result.classification.get('eu_tier')}; "
        f"India context sensitivity {result.classification.get('india_sensitivity')}",
        "",
        "## Factors",
        f"- **Groups evaluated:** {_text(spec.sensitive_features)}",
        "",
        "## Metrics (measured in this audit)",
    ]
    if perf and perf.status not in (Status.SKIPPED, Status.ERROR):
        m = perf.metrics
        lines += [
            f"- **ROC AUC:** {m['auc']:.3f} (95% CI {m['auc_ci_low']:.3f}–{m['auc_ci_high']:.3f}); "
            f"documented claim: {_text(_get(doc, 'metrics.claimed.auc'))}",
            f"- **Accuracy / F1 at threshold {spec.decision_threshold}:** {m['accuracy']:.3f} / {m['f1']:.3f}",
        ]
    if cal and cal.status not in (Status.SKIPPED, Status.ERROR):
        lines.append(f"- **Calibration (ECE):** {cal.metrics['ece']:.3f}")
    if parity and parity.status not in (Status.SKIPPED, Status.ERROR):
        for key, value in parity.metrics.items():
            if key.startswith("di_") and value is not None:
                lines.append(f"- **Disparate impact ratio, {key[3:]}:** {value:.2f}")
    if drivers and drivers.status not in (Status.SKIPPED, Status.ERROR):
        top = ", ".join(r["feature"] for r in drivers.details["ranking"][:5])
        lines.append(f"- **Top decision drivers (permutation importance):** {top}")
    lines += [
        "",
        "## Data",
        f"- **Training data:** {_text(_get(doc, 'training_data.description'))}",
        f"- **Provenance:** {_text(_get(doc, 'training_data.provenance'))}",
        f"- **Evaluation data:** {_text(_get(doc, 'evaluation_data.description'))}",
        "",
        "## Human oversight",
        f"- **Measures:** {_text(_get(doc, 'human_oversight.measures'))}",
        f"- **Override and appeal:** {_text(_get(doc, 'human_oversight.override_process'))}",
        "",
        "## Ethical considerations",
        _text(_get(doc, "ethical_considerations")),
        "",
        "## Caveats and limitations",
        _text(_get(doc, "caveats_and_limitations")),
        "",
        "## Open audit findings",
    ]
    open_risks = [r for r in result.risks if not r.accepted]
    if open_risks:
        lines += [f"- **{r.risk_id} ({r.rating.value}):** {r.description}" for r in open_risks]
    else:
        lines.append("None.")
    lines += ["", f"_Evidence root hash: `{result.ledger_root}`_", ""]
    return "\n".join(lines)


def _load(spec) -> dict[str, Any]:
    import yaml

    path = spec.artifact("documentation")
    if path is None or not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
