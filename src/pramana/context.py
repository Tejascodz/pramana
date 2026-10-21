"""Audit context: lazily loads the artifacts under audit and caches derived values."""

from __future__ import annotations

import json
from datetime import date
from functools import cached_property
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import yaml

from pramana.adapters.llm import LLMClient, build_client
from pramana.spec import AuditSpec


class MissingArtifact(RuntimeError):
    """Raised by a check when an artifact it needs was not supplied."""


class AuditContext:
    def __init__(self, spec: AuditSpec, audit_date: date | None = None):
        self.spec = spec
        self.audit_date = audit_date or date.today()
        self.rng = np.random.default_rng(spec.seed)

    # Tabular artifacts ---------------------------------------------------

    def _read_table(self, key: str) -> pd.DataFrame | None:
        path = self.spec.artifact(key)
        if path is None:
            return None
        if not path.exists():
            raise MissingArtifact(f"artifacts.{key} not found: {path.name}")
        if path.suffix.lower() == ".parquet":
            return pd.read_parquet(path)
        return pd.read_csv(path)

    @cached_property
    def eval_df(self) -> pd.DataFrame:
        df = self._read_table("evaluation_data")
        if df is None:
            raise MissingArtifact("artifacts.evaluation_data is required")
        return df

    @cached_property
    def ref_df(self) -> pd.DataFrame | None:
        return self._read_table("reference_data")

    @cached_property
    def prod_df(self) -> pd.DataFrame | None:
        return self._read_table("production_data")

    @property
    def has_model(self) -> bool:
        return self.spec.artifact("model") is not None

    @cached_property
    def model(self) -> Any:
        path = self.spec.artifact("model")
        if path is None:
            raise MissingArtifact("No model artifact supplied (predictions-only audit)")
        if not path.exists():
            raise MissingArtifact(f"Model file not found: {path.name}")
        # Model files are pickles and can execute code when loaded. Only audit
        # models received through a trusted, access-controlled channel.
        return joblib.load(path)

    @cached_property
    def feature_columns(self) -> list[str]:
        if self.spec.features:
            return list(self.spec.features)
        skip = {self.spec.target, self.spec.score_column, *self.spec.sensitive_features}
        skip.update(self.spec.exclude_columns)
        return [c for c in self.eval_df.columns if c not in skip]

    def X(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[self.feature_columns]

    def y(self, df: pd.DataFrame) -> np.ndarray:
        return (df[self.spec.target] == self.spec.positive_label).astype(int).to_numpy()

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Probability of the positive class for each row."""
        if not self.has_model:
            if self.spec.score_column and self.spec.score_column in df.columns:
                return df[self.spec.score_column].to_numpy(dtype=float)
            raise MissingArtifact("Scores need a model or a score_column")
        model = self.model
        X = self.X(df)
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)
            classes = list(getattr(model, "classes_", [0, 1]))
            col = (
                classes.index(self.spec.positive_label)
                if self.spec.positive_label in classes
                else -1
            )
            return np.asarray(proba)[:, col]
        return np.asarray(model.predict(X), dtype=float)

    def decide(self, scores: np.ndarray) -> np.ndarray:
        return (scores >= self.spec.decision_threshold).astype(int)

    @cached_property
    def eval_y(self) -> np.ndarray:
        return self.y(self.eval_df)

    @cached_property
    def eval_scores(self) -> np.ndarray:
        return self.score(self.eval_df)

    @cached_property
    def eval_pred(self) -> np.ndarray:
        return self.decide(self.eval_scores)

    @cached_property
    def numeric_features(self) -> list[str]:
        X = self.X(self.eval_df)
        return [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]

    # Documentation -------------------------------------------------------

    @cached_property
    def documentation(self) -> dict[str, Any] | None:
        path = self.spec.artifact("documentation")
        if path is None or not path.exists():
            return None
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    # LLM applications ----------------------------------------------------

    @cached_property
    def llm_client(self) -> LLMClient:
        if not self.spec.llm:
            raise MissingArtifact("No 'llm' section in the spec")
        return build_client(self.spec.llm)

    @cached_property
    def probes(self) -> dict[str, Any]:
        path = self.spec.llm.get("probes")
        if not path:
            raise MissingArtifact("llm.probes is required for LLM checks")
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        canary = str(data.get("canary", ""))

        def fill(value: Any) -> Any:
            if isinstance(value, str):
                return value.replace("{canary}", canary)
            if isinstance(value, list):
                return [fill(v) for v in value]
            if isinstance(value, dict):
                return {k: fill(v) for k, v in value.items()}
            return value

        return fill(data)

    @cached_property
    def knowledge_base(self) -> str:
        path = self.spec.llm.get("knowledge_base")
        return Path(path).read_text(encoding="utf-8") if path else ""

    @cached_property
    def llm_transcript(self) -> list[dict[str, Any]]:
        """Every prompt/response exchanged during the audit, kept as evidence."""
        return []

    def ask(self, category: str, probe: dict[str, Any]) -> str:
        system = self.probes.get("system_prompt", "")
        response = self.llm_client.complete(system, probe["prompt"])
        self.llm_transcript.append(
            {
                "category": category,
                "probe_id": probe["id"],
                "prompt": probe["prompt"],
                "response": response,
            }
        )
        return response

    # Agents ---------------------------------------------------------------

    @cached_property
    def agent_events(self) -> list[dict[str, Any]]:
        path = self.spec.agent.get("trace")
        if not path:
            raise MissingArtifact("agent.trace is required for agent checks")
        events = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events
