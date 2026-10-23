"""Audit engine. Runs the five SMACTR stages from Raji et al. (2020):

Scoping -> Mapping -> Artifact collection -> Testing -> Reflection

Every stage writes its outputs to the evidence ledger, so the final pack shows
not only what was found but how the audit reached it.
"""

from __future__ import annotations

import json
import platform
import traceback
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pramana import __version__
from pramana.audit.ledger import EvidenceLedger
from pramana.context import AuditContext, MissingArtifact
from pramana.controls import ControlLibrary, load_library
from pramana.registry import CheckDefinition, all_checks, checks_for
from pramana.risk.scoring import audit_opinion, build_register, gate_decision
from pramana.spec import AuditSpec
from pramana.types import CheckResult, Risk, Severity, Status

COVERAGE_STATES = ("evidenced", "partial", "deficient", "not tested", "not applicable")
DUE_DAYS = {Severity.CRITICAL: 14, Severity.HIGH: 30, Severity.MEDIUM: 90, Severity.LOW: 180}


@dataclass
class AuditResult:
    audit_id: str
    spec: AuditSpec
    audit_date: date
    started: str
    finished: str
    results: list[CheckResult]
    risks: list[Risk]
    gate: dict[str, Any]
    opinion: dict[str, str]
    classification: dict[str, Any]
    fmea: list[dict[str, Any]]
    coverage: dict[str, Any]
    remediation: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    manual_evidence: list[dict[str, Any]]
    llm_transcript: list[dict[str, Any]] = field(default_factory=list)
    llm_run: dict[str, Any] = field(default_factory=dict)
    ledger_root: str | None = None
    environment: dict[str, str] = field(default_factory=dict)
    ledger: EvidenceLedger | None = field(default=None, repr=False)

    @property
    def counts(self) -> dict[str, int]:
        return dict(Counter(r.status.value for r in self.results))

    def result(self, check_id: str) -> CheckResult | None:
        return next((r for r in self.results if r.check_id == check_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "tool": {"name": "pramana", "version": __version__},
            "system": self.spec.system,
            "use_case": self.spec.use_case,
            "audit_date": self.audit_date.isoformat(),
            "started": self.started,
            "finished": self.finished,
            "opinion": self.opinion,
            "gate": self.gate,
            "counts": self.counts,
            "classification": self.classification,
            "results": [r.to_dict() for r in self.results],
            "risks": [r.to_dict() for r in self.risks],
            "fmea": self.fmea,
            "coverage": self.coverage,
            "remediation": self.remediation,
            "artifacts": self.artifacts,
            "manual_evidence": self.manual_evidence,
            "llm_run": self.llm_run,
            "ledger_root": self.ledger_root,
            "environment": self.environment,
        }


def _where(exc: BaseException) -> str:
    """File name and line of the failure, without absolute paths."""
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return ""
    last = frames[-1]
    return f"{Path(last.filename).name}:{last.lineno} in {last.name}"


def _run_check(definition: CheckDefinition, ctx: AuditContext) -> CheckResult:
    try:
        return definition.fn(ctx)
    except MissingArtifact as exc:
        return CheckResult(
            check_id=definition.check_id,
            title=definition.title,
            category=definition.category,
            status=Status.SKIPPED,
            summary=f"Skipped: {exc}",
            plain_summary="Not tested because the required input was not supplied.",
        )
    except Exception as exc:  # noqa: BLE001 - a crashing check must not end the audit
        return CheckResult(
            check_id=definition.check_id,
            title=definition.title,
            category=definition.category,
            status=Status.ERROR,
            severity=Severity.MEDIUM,
            summary=f"Check raised {type(exc).__name__}: {exc}",
            plain_summary="This test could not be completed and needs manual follow-up.",
            recommendation="Fix the input or the check and re-run the audit.",
            details={"location": _where(exc)},
        )


def _extra_types(spec: AuditSpec) -> tuple[str, ...]:
    extra = []
    if spec.llm:
        extra.append("llm_application")
    if spec.agent.get("trace"):
        extra.append("agent")
    return tuple(extra)


GENAI_FRAMEWORKS = {"NIST-GAI", "OWASP-LLM"}
GENAI_TYPES = {"llm_application", "agent"}
# The agentic Top 10 describes risks of systems that act through tools; a chatbot audit
# would otherwise show it as ten uncovered controls.
AGENT_FRAMEWORKS = {"OWASP-ASI"}


def _control_applicable(control, eu_tier: str, system_types: set[str]) -> bool:
    if control.framework in GENAI_FRAMEWORKS and not system_types & GENAI_TYPES:
        return False
    if control.framework in AGENT_FRAMEWORKS and "agent" not in system_types:
        return False
    if control.framework != "EUAIA":
        return True
    return "all" in control.applies_to or eu_tier in control.applies_to


def compute_coverage(
    library: ControlLibrary,
    results: list[CheckResult],
    manual: list[dict[str, Any]],
    eu_tier: str,
    accepted_checks: set[str],
    system_types: set[str],
) -> dict[str, Any]:
    by_check = {r.check_id: r for r in results if r.status not in (Status.SKIPPED, Status.ERROR)}
    manual_by_ref: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in manual:
        if item.get("present"):
            manual_by_ref[item["control"]].append(item)

    controls = []
    for control in library.all_controls():
        ref = control.ref
        if not _control_applicable(control, eu_tier, system_types):
            state, checks = "not applicable", []
        else:
            checks = [c for c in library.checks_for_control(ref) if c in by_check]
            statuses = {by_check[c].status for c in checks if c not in accepted_checks}
            if Status.FAIL in statuses:
                state = "deficient"
            elif Status.WARN in statuses:
                state = "partial"
            elif checks or manual_by_ref.get(ref):
                state = "evidenced"
            else:
                state = "not tested"
        controls.append(
            {
                "ref": ref,
                "framework": control.framework,
                "id": control.id,
                "group": control.group,
                "title": control.title,
                "evidence_type": control.evidence,
                "state": state,
                "checks": checks,
                "manual_evidence": [m["file_name"] for m in manual_by_ref.get(ref, [])],
            }
        )

    frameworks = {}
    for fw in library.frameworks.values():
        rows = [c for c in controls if c["framework"] == fw.id]
        groups: dict[str, Counter] = defaultdict(Counter)
        for c in rows:
            groups[c["group"]][c["state"]] += 1
        frameworks[fw.id] = {
            "name": fw.name,
            "version": fw.version,
            "source": fw.source,
            "group_label": fw.group_label,
            "totals": {s: sum(1 for c in rows if c["state"] == s) for s in COVERAGE_STATES},
            "groups": {
                g: {s: counts.get(s, 0) for s in COVERAGE_STATES} for g, counts in groups.items()
            },
        }
    return {"controls": controls, "frameworks": frameworks}


def _remediation(risks: list[Risk], audit_date: date) -> list[dict[str, Any]]:
    plan = []
    for risk in risks:
        if risk.accepted:
            continue
        days = DUE_DAYS.get(risk.rating, 180)
        plan.append(
            {
                "risk_id": risk.risk_id,
                "priority": {
                    Severity.CRITICAL: "P1",
                    Severity.HIGH: "P1",
                    Severity.MEDIUM: "P2",
                }.get(risk.rating, "P3"),
                "action": risk.recommendation,
                "owner": risk.owner,
                "due": (audit_date + timedelta(days=days)).isoformat(),
                "closes_controls": risk.controls,
            }
        )
    return plan


def run_audit(spec: AuditSpec, out_dir: Path, audit_date: date | None = None) -> AuditResult:
    # Pinned artifacts are checked before anything is read or unpickled.
    spec.verify_artifacts()
    library = load_library()
    ctx = AuditContext(spec, audit_date=audit_date)
    ledger = EvidenceLedger(Path(out_dir))
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    audit_id = f"PRM-{ctx.audit_date:%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"
    definitions = [
        d
        for d in checks_for(spec.system_type, _extra_types(spec))
        if spec.check_enabled(d.check_id)
    ]

    # 1. Scoping ------------------------------------------------------------
    classification_def = next(
        d for d in all_checks() if d.check_id == "governance.risk_classification"
    )
    classification = _run_check(classification_def, ctx)
    eu_tier = classification.details.get("eu_tier", "minimal")
    ledger.add_json(
        "1-scoping",
        "system_profile",
        {
            "audit_id": audit_id,
            "system": spec.system,
            "use_case": spec.use_case,
            "classification": classification.details,
            "thresholds": spec.thresholds,
            "planned_checks": [d.check_id for d in definitions],
        },
    )

    # 2. Mapping ------------------------------------------------------------
    fmea = []
    for d in definitions:
        entry = library.crosswalk.get(d.check_id, {})
        fmea.append(
            {
                "check_id": d.check_id,
                "failure_mode": entry.get("failure_mode", ""),
                "effect": entry.get("effect", ""),
                "detection": d.title,
                "controls": entry.get("controls", []),
            }
        )
    raci = spec.governance.get("raci", {})
    ledger.add_json("2-mapping", "fmea", fmea)
    ledger.add_json("2-mapping", "raci", raci)

    # 3. Artifact collection ----------------------------------------------
    artifacts = []
    for key, path in spec.artifacts.items():
        if path is not None and path.exists():
            digest = ledger.add_external("3-artifacts", key, path)
            artifacts.append({"artifact": key, "file": path.name, "sha256": digest})
        else:
            artifacts.append({"artifact": key, "file": path.name if path else None, "sha256": None})
    for key in ("trace",):
        if spec.agent.get(key) and Path(spec.agent[key]).exists():
            digest = ledger.add_external("3-artifacts", f"agent_{key}", spec.agent[key])
            artifacts.append(
                {"artifact": f"agent_{key}", "file": Path(spec.agent[key]).name, "sha256": digest}
            )
    for key in ("probes", "replay", "knowledge_base"):
        if spec.llm.get(key) and Path(spec.llm[key]).exists():
            digest = ledger.add_external("3-artifacts", f"llm_{key}", spec.llm[key])
            artifacts.append(
                {"artifact": f"llm_{key}", "file": Path(spec.llm[key]).name, "sha256": digest}
            )

    manual = []
    for item in spec.governance.get("manual_evidence", []):
        path = Path(item["file"])
        present = path.exists()
        record = {
            "control": item["control"],
            "description": item.get("description", ""),
            "owner": item.get("owner", ""),
            "file_name": path.name,
            "present": present,
            "sha256": ledger.add_external("3-artifacts", f"manual:{item['control']}", path)
            if present
            else None,
        }
        manual.append(record)
    ledger.add_json("3-artifacts", "manifest", {"artifacts": artifacts, "manual_evidence": manual})

    # 4. Testing ------------------------------------------------------------
    results = [classification]
    for d in definitions:
        if d.check_id == "governance.risk_classification":
            continue
        results.append(_run_check(d, ctx))
    missing_manual = [m for m in manual if not m["present"]]
    if spec.governance.get("manual_evidence"):
        results.append(
            CheckResult(
                check_id="governance.manual_evidence",
                title="Governance evidence on file",
                category="Governance",
                status=Status.WARN if missing_manual else Status.PASS,
                severity=Severity.MEDIUM if missing_manual else Severity.INFO,
                summary=(
                    f"{len(manual) - len(missing_manual)}/{len(manual)} referenced governance documents were "
                    "supplied and fingerprinted."
                    + (
                        " Missing: "
                        + ", ".join(f"{m['file_name']} ({m['control']})" for m in missing_manual)
                        + "."
                        if missing_manual
                        else ""
                    )
                ),
                plain_summary=(
                    "Some governance documents that were cited as evidence could not be produced."
                    if missing_manual
                    else "Every governance document cited as evidence was produced."
                ),
                recommendation="Provide each cited document, or remove the claim from the control register.",
                metrics={"documents": len(manual), "missing": len(missing_manual)},
            )
        )
    for r in results:
        r.controls = library.controls_for_check(r.check_id)
        r.evidence_hash = ledger.add_json("4-testing", r.check_id, r.to_dict())
    llm_run = ctx.llm_run_summary() if spec.llm else {}
    if ctx.llm_transcript:
        ledger.add_json("4-testing", "llm_transcript", ctx.llm_transcript)
        ledger.add_json("4-testing", "llm_run", llm_run)
        replay = "\n".join(json.dumps(r, ensure_ascii=False) for r in ctx.replay_records()) + "\n"
        ledger.add_text("4-testing", "llm_replay", "llm_replay.jsonl", replay)

    # 5. Reflection ---------------------------------------------------------
    today = ctx.audit_date
    risks = build_register(
        results,
        eu_tier=eu_tier,
        raci=raci,
        acceptances=spec.governance.get("risk_acceptances", []) or [],
        today=today,
    )
    incomplete = [r.check_id for r in results if r.status == Status.ERROR]
    gate = gate_decision(risks, spec.gate, incomplete)
    opinion = audit_opinion(risks, incomplete)
    process = CheckResult(
        check_id="audit.process",
        title="Documented go/no-go decision",
        category="Governance",
        status=Status.PASS,
        summary=(
            f"Test plan (FMEA, {len(fmea)} failure modes), scored risk register ({len(risks)} risks), "
            f"treatment plan and release-gate decision ({gate['decision']}) recorded in this audit pack."
        ),
        plain_summary="A documented, risk-based release decision exists for this version.",
        controls=library.controls_for_check("audit.process"),
    )
    process.evidence_hash = ledger.add_json("5-reflection", "audit.process", process.to_dict())
    results.append(process)

    accepted_checks = {r.source_check for r in risks if r.accepted}
    system_types = {spec.system_type, *_extra_types(spec)}
    coverage = compute_coverage(library, results, manual, eu_tier, accepted_checks, system_types)
    remediation = _remediation(risks, today)
    ledger.add_json("5-reflection", "risk_register", [r.to_dict() for r in risks])
    ledger.add_json("5-reflection", "gate", {"gate": gate, "opinion": opinion})
    ledger.add_json("5-reflection", "control_coverage", coverage)
    ledger.add_json("5-reflection", "remediation_plan", remediation)

    return AuditResult(
        audit_id=audit_id,
        spec=spec,
        audit_date=today,
        started=started,
        finished=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        results=results,
        risks=risks,
        gate=gate,
        opinion=opinion,
        classification=classification.details,
        fmea=fmea,
        coverage=coverage,
        remediation=remediation,
        artifacts=artifacts,
        manual_evidence=manual,
        llm_transcript=list(ctx.llm_transcript),
        llm_run=llm_run,
        ledger_root=ledger.root_hash,
        environment={"python": platform.python_version(), "pramana": __version__},
        ledger=ledger,
    )
