"""Audit specification: the single YAML file that describes what is being audited."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

SYSTEM_TYPES = {"tabular_classifier", "llm_application", "agent"}

DEFAULT_THRESHOLDS: dict[str, float] = {
    "min_auc": 0.70,
    "disparate_impact_min": 0.80,
    "equalized_odds_max": 0.10,
    "min_group_size": 30,
    "proxy_auc_max": 0.70,
    "noise_flip_rate_max": 0.05,
    "ece_max": 0.05,
    "psi_warn": 0.10,
    "psi_fail": 0.25,
    "mia_auc_max": 0.60,
    "missing_rate_max": 0.05,
    "duplicate_rate_max": 0.01,
    "leakage_auc_max": 0.95,
    "model_card_min_completeness": 0.85,
    "llm_attack_success_max": 0.0,
    "llm_groundedness_min": 0.90,
    "agent_auditability_min": 0.90,
    "agent_reasoning_coverage_min": 0.80,
    "llm_latency_p95_max_ms": 20000,
    "llm_max_output_chars": 4000,
}


class SpecError(ValueError):
    """Raised when an audit specification is missing required information."""


class ArtifactIntegrityError(SpecError):
    """An artifact does not match the SHA-256 pinned for it in ``artifacts_sha256``."""


@dataclass
class AuditSpec:
    path: Path
    system: dict[str, Any]
    use_case: dict[str, Any]
    artifacts: dict[str, Path]
    target: str | None = None
    features: list[str] | None = None
    sensitive_features: list[str] = field(default_factory=list)
    exclude_columns: list[str] = field(default_factory=list)
    positive_label: Any = 1
    decision_threshold: float = 0.5
    score_column: str | None = None
    thresholds: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    checks: dict[str, Any] = field(default_factory=dict)
    llm: dict[str, Any] = field(default_factory=dict)
    agent: dict[str, Any] = field(default_factory=dict)
    governance: dict[str, Any] = field(default_factory=dict)
    gate: dict[str, Any] = field(default_factory=dict)
    seed: int = 7
    artifacts_sha256: dict[str, str] = field(default_factory=dict)

    def verify_artifact(self, key: str) -> None:
        """Raise ArtifactIntegrityError if the artifact differs from its pinned hash."""
        expected = self.artifacts_sha256.get(key)
        path = self.artifacts.get(key)
        if not expected or path is None or not Path(path).exists():
            return
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ArtifactIntegrityError(
                f"artifacts.{key} ({Path(path).name}) does not match its pinned SHA-256; "
                "refusing to audit it"
            )

    def verify_artifacts(self) -> None:
        for key in self.artifacts_sha256:
            self.verify_artifact(key)

    @property
    def base_dir(self) -> Path:
        return self.path.parent

    @property
    def system_type(self) -> str:
        return self.system["type"]

    @property
    def name(self) -> str:
        return self.system["name"]

    def artifact(self, key: str) -> Path | None:
        return self.artifacts.get(key)

    def threshold(self, key: str) -> float:
        return float(self.thresholds.get(key, DEFAULT_THRESHOLDS[key]))

    def check_enabled(self, check_id: str) -> bool:
        include = self.checks.get("include")
        exclude = set(self.checks.get("exclude", []))
        if check_id in exclude:
            return False
        return include is None or check_id in include

    def check_options(self, check_id: str) -> dict[str, Any]:
        return dict(self.checks.get("options", {}).get(check_id, {}))


def _resolve(base: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    return path if path.is_absolute() else (base / path)


def load_spec(path: str | Path) -> AuditSpec:
    spec_path = Path(path)
    if not spec_path.exists():
        raise SpecError(f"Spec file not found: {spec_path}")
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}

    for key in ("system", "use_case"):
        if key not in raw:
            raise SpecError(f"Spec is missing the '{key}' section")
    system = raw["system"]
    for key in ("name", "version", "type", "owner"):
        if key not in system:
            raise SpecError(f"system.{key} is required")
    if system["type"] not in SYSTEM_TYPES:
        raise SpecError(
            f"system.type must be one of {sorted(SYSTEM_TYPES)}, got '{system['type']}'"
        )

    base = spec_path.parent
    artifacts = {k: _resolve(base, v) for k, v in (raw.get("artifacts") or {}).items()}

    if system["type"] == "tabular_classifier":
        if "evaluation_data" not in artifacts:
            raise SpecError("artifacts.evaluation_data is required for tabular_classifier systems")
        if "model" not in artifacts and not raw.get("score_column"):
            raise SpecError(
                "tabular_classifier audits need artifacts.model, or a score_column in the "
                "evaluation data for a predictions-only audit"
            )
        if "target" not in raw:
            raise SpecError("'target' column is required for tabular_classifier systems")

    pins_raw = raw.get("artifacts_sha256") or {}
    if not isinstance(pins_raw, dict):
        raise SpecError("artifacts_sha256 must map artifact names to SHA-256 hashes")
    pins: dict[str, str] = {}
    for key, value in pins_raw.items():
        if key not in artifacts:
            raise SpecError(
                f"artifacts_sha256.{key} pins an artifact that is not under 'artifacts'"
            )
        digest = str(value).strip().lower()
        if not _SHA256_HEX.match(digest):
            raise SpecError(f"artifacts_sha256.{key} must be a 64-character hex SHA-256")
        pins[key] = digest

    thresholds = dict(DEFAULT_THRESHOLDS)
    thresholds.update(raw.get("thresholds") or {})

    llm = dict(raw.get("llm") or {})
    for key in ("probes", "replay", "knowledge_base"):
        if key in llm:
            llm[key] = _resolve(base, llm[key])

    agent = dict(raw.get("agent") or {})
    if "trace" in agent:
        agent["trace"] = _resolve(base, agent["trace"])

    governance = dict(raw.get("governance") or {})
    manual = []
    for item in governance.get("manual_evidence", []) or []:
        entry = dict(item)
        entry["file"] = _resolve(base, entry["file"])
        manual.append(entry)
    governance["manual_evidence"] = manual

    return AuditSpec(
        path=spec_path,
        system=system,
        use_case=raw["use_case"],
        artifacts=artifacts,
        target=raw.get("target"),
        features=raw.get("features"),
        sensitive_features=list(raw.get("sensitive_features") or []),
        exclude_columns=list(raw.get("exclude_columns") or []),
        positive_label=raw.get("positive_label", 1),
        decision_threshold=float(raw.get("decision_threshold", 0.5)),
        score_column=raw.get("score_column"),
        thresholds=thresholds,
        checks=dict(raw.get("checks") or {}),
        llm=llm,
        agent=agent,
        governance=governance,
        gate=dict(raw.get("gate") or {}),
        seed=int(raw.get("seed", 7)),
        artifacts_sha256=pins,
    )


SPEC_TEMPLATE = """\
# Pramana audit specification. See docs/methodology.md for every field.
system:
  name: My Credit Model
  version: 1.0.0
  type: tabular_classifier        # tabular_classifier | llm_application | agent
  owner: Model Owner Team
  accountable_executive: Chief Risk Officer
  description: One paragraph on what the system does.

use_case:
  domain: credit_scoring          # see `pramana classify --help` for known domains
  purpose: Pre-screen personal loan applications.
  decision_role: decision_support # decision_support | automated_decision
  affected_persons: Retail loan applicants
  deployment_regions: [IN]
  processes_personal_data: true
  interacts_with_people: false
  generates_synthetic_content: false
  prohibited_practice_flags: []

artifacts:
  model: model.joblib
  reference_data: data/train.csv
  evaluation_data: data/test.csv
  production_data: data/production.csv
  documentation: model_card.yaml

# Optional: refuse to audit (or unpickle) an artifact whose SHA-256 differs from this.
# Get a hash with `shasum -a 256 model.joblib` (macOS) or `sha256sum model.joblib`.
# artifacts_sha256:
#   model: <64 hex characters>

# For type: agent, the agent section can also declare:
#   identity: agent:refund-bot           # the agent's own identity, not a user's token
#   interrupt_conditions: [refund total above INR 50,000 in an hour]
#   monitor: second-model review of every tool call

target: label
positive_label: 1
decision_threshold: 0.5
sensitive_features: [gender]
exclude_columns: [id]

thresholds:
  min_auc: 0.70

governance:
  raci:
    model_owner: Model Owner Team
    risk_owner: Model Risk Management
    approver: Chief Risk Officer
  manual_evidence: []
  risk_acceptances: []

gate:
  block_on: [critical, high]
"""
