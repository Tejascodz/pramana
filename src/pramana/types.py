"""Core data types shared across the audit pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def is_finding(self) -> bool:
        return self in (Status.WARN, Status.FAIL)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)

    @classmethod
    def from_score(cls, score: int) -> Severity:
        """Map a likelihood x impact score (1-25) onto a severity band."""
        if score >= 20:
            return cls.CRITICAL
        if score >= 12:
            return cls.HIGH
        if score >= 6:
            return cls.MEDIUM
        if score >= 3:
            return cls.LOW
        return cls.INFO


@dataclass
class CheckResult:
    """Outcome of one audit check.

    ``summary`` is written for the technical reviewer; ``plain_summary`` is the
    one-sentence version used in the executive summary.
    """

    check_id: str
    title: str
    category: str
    status: Status
    severity: Severity = Severity.INFO
    summary: str = ""
    plain_summary: str = ""
    recommendation: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    controls: list[str] = field(default_factory=list)
    evidence_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


@dataclass
class Risk:
    """Entry in the audit risk register."""

    risk_id: str
    title: str
    description: str
    source_check: str
    likelihood: int
    impact: int
    owner: str
    treatment: str
    recommendation: str
    controls: list[str] = field(default_factory=list)
    accepted: bool = False
    acceptance: dict[str, Any] | None = None

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def rating(self) -> Severity:
        return Severity.from_score(self.score)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["score"] = self.score
        data["rating"] = self.rating.value
        return data
