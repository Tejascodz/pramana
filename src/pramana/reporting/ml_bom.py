"""CycloneDX 1.7 ML bill of materials for the audited system.

The ML-BOM lists what was audited (the model or application, and the data and trace files,
each with its SHA-256) and what the audit measured, in the machine-readable format that
supply-chain and AI-inventory tools read. It is generated from the same results as the
report and is sealed in the ledger with the other outputs. The structure follows the
CycloneDX 1.7 JSON schema (ECMA-424); tests validate it against the official schema when
the ``cyclonedx-python-lib`` package is installed.
"""

from __future__ import annotations

import uuid
from typing import Any

from pramana import __version__
from pramana.types import Status

SPEC_VERSION = "1.7"
_MEASURED = (Status.PASS, Status.WARN, Status.FAIL)
_DATASETS = {
    "reference_data", "evaluation_data", "production_data", "agent_trace", "llm_replay",
    "llm_knowledge_base",
}  # fmt: skip

# Metrics worth carrying into the BOM, by check: (metric key, CycloneDX metric type label).
_PERFORMANCE = (("auc", "AUC"), ("accuracy", "accuracy"), ("precision", "precision"),
                ("recall", "recall"), ("f1", "F1"))  # fmt: skip
_CALIBRATION = (("ece", "expected calibration error"),
                ("adaptive_ece", "expected calibration error (equal-mass bins)"),
                ("brier", "Brier score"))  # fmt: skip


def _metric(kind: str, value: Any, low: Any = None, high: Any = None, slice_: str = "") -> dict:
    entry: dict[str, Any] = {"type": kind, "value": f"{float(value):.4g}"}
    if slice_:
        entry["slice"] = slice_
    if low is not None and high is not None:
        entry["confidenceInterval"] = {"lowerBound": f"{low:.4g}", "upperBound": f"{high:.4g}"}
    return entry


def _measured(result, check_id: str):
    r = result.result(check_id)
    return r if r is not None and r.status in _MEASURED else None


def _performance_metrics(result) -> list[dict[str, Any]]:
    out = []
    perf = _measured(result, "performance.discrimination")
    if perf:
        for key, label in _PERFORMANCE:
            if perf.metrics.get(key) is not None:
                ci = (perf.metrics.get("auc_ci_low"), perf.metrics.get("auc_ci_high"))
                out.append(
                    _metric(label, perf.metrics[key], *(ci if key == "auc" else (None, None)))
                )
    cal = _measured(result, "calibration.reliability")
    if cal:
        for key, label in _CALIBRATION:
            if cal.metrics.get(key) is not None:
                out.append(_metric(label, cal.metrics[key]))
    parity = _measured(result, "fairness.group_parity")
    if parity:
        for attr, data in parity.details.get("attributes", {}).items():
            di = data["summary"].get("disparate_impact_ratio")
            if di is not None and di == di:  # skip NaN
                out.append(_metric("disparate impact ratio", di, slice_=attr))
    return out


def _fairness_assessments(result) -> list[dict[str, str]]:
    parity = _measured(result, "fairness.group_parity")
    if not parity:
        return []
    out = []
    for attr, data in parity.details.get("attributes", {}).items():
        s = data["summary"]
        if s.get("least_favoured") is None or data["status"] == Status.PASS.value:
            continue
        out.append(
            {
                "groupAtRisk": f"{attr}={s['least_favoured']}",
                "harms": (
                    f"Favourable-outcome rate {s['disparate_impact_ratio']:.2f} times that of "
                    f"{attr}={s['most_favoured']}"
                ),
                "mitigationStrategy": parity.recommendation,
            }
        )
    return out


def render_ml_bom(result) -> dict[str, Any]:
    spec = result.spec
    tabular = spec.system_type == "tabular_classifier"
    artifacts = {a["artifact"]: a for a in result.artifacts if a.get("sha256")}

    component: dict[str, Any] = {
        "type": "machine-learning-model" if tabular else "application",
        "bom-ref": "audited-system",
        "name": str(spec.name),
        "version": str(spec.system.get("version", "")),
    }
    if spec.system.get("description"):
        component["description"] = " ".join(str(spec.system["description"]).split())
    if tabular and "model" in artifacts:
        component["hashes"] = [{"alg": "SHA-256", "content": artifacts["model"]["sha256"]}]

    considerations: dict[str, Any] = {}
    if spec.use_case.get("purpose"):
        considerations["useCases"] = [str(spec.use_case["purpose"])]
    if spec.use_case.get("affected_persons"):
        considerations["users"] = [str(spec.use_case["affected_persons"])]
    open_risks = [r for r in result.risks if not r.accepted]
    if open_risks:
        considerations["ethicalConsiderations"] = [
            {"name": f"{r.risk_id}: {r.title}", "mitigationStrategy": r.recommendation}
            for r in open_risks
        ]
    fairness = _fairness_assessments(result)
    if fairness:
        considerations["fairnessAssessments"] = fairness

    model_card: dict[str, Any] = {}
    if tabular:
        model_card["modelParameters"] = {
            "approach": {"type": "supervised"},
            "task": "binary classification",
        }
    metrics = _performance_metrics(result)
    if metrics:
        model_card["quantitativeAnalysis"] = {"performanceMetrics": metrics}
    if considerations:
        model_card["considerations"] = considerations
    if model_card:
        component["modelCard"] = model_card

    component["properties"] = [
        {"name": "pramana:audit_id", "value": result.audit_id},
        {"name": "pramana:audit_date", "value": str(result.audit_date)},
        {"name": "pramana:owner", "value": str(spec.system.get("owner", ""))},
        {"name": "pramana:gate_decision", "value": str(result.gate.get("decision", ""))},
        {"name": "pramana:opinion", "value": str(result.opinion.get("rating", ""))},
        {"name": "pramana:eu_ai_act_tier", "value": str(result.classification.get("eu_tier", ""))},
    ]

    components = []
    for key, art in artifacts.items():
        if tabular and key == "model":
            continue
        entry: dict[str, Any] = {"bom-ref": f"artifact-{key}", "name": art["file"]}
        if key in _DATASETS:
            entry.update(type="data", data=[{"type": "dataset", "name": key}])
        else:  # documentation, probe sets: files, not data
            entry["type"] = "file"
        entry["hashes"] = [{"alg": "SHA-256", "content": art["sha256"]}]
        components.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": uuid.uuid5(uuid.NAMESPACE_URL, f"urn:pramana:{result.audit_id}").urn,
        "version": 1,
        "metadata": {
            "timestamp": result.finished,
            "tools": {
                "components": [{"type": "application", "name": "pramana", "version": __version__}]
            },
            "component": component,
        },
        "components": components,
        "dependencies": [
            {"ref": "audited-system", "dependsOn": [c["bom-ref"] for c in components]}
        ],
    }
