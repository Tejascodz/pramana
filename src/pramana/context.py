"""Audit context: lazily loads the artifacts under audit and caches derived values."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import date
from functools import cached_property
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import yaml

from pramana.adapters.llm import Completion, EndpointUnavailable, LLMClient, build_client
from pramana.probes import load_probe_file
from pramana.spec import AuditSpec


class MissingArtifact(RuntimeError):
    """Raised by a check when an artifact it needs was not supplied."""


class AuditContext:
    def __init__(self, spec: AuditSpec, audit_date: date | None = None):
        self.spec = spec
        self.audit_date = audit_date or date.today()
        self.rng = np.random.default_rng(spec.seed)
        self._preflight: dict[str, Any] | Exception | None = None

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
        # models received through a trusted, access-controlled channel, and pin their hash
        # in artifacts_sha256 so a swapped file is refused before it is unpickled.
        self.spec.verify_artifact("model")
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

    @property
    def llm_is_live(self) -> bool:
        return self.spec.llm.get("mode", "replay") != "replay"

    @property
    def llm_samples(self) -> int:
        return max(1, int(self.spec.llm.get("samples", 1)))

    @cached_property
    def probes(self) -> dict[str, Any]:
        path = self.spec.llm.get("probes")
        if not path:
            raise MissingArtifact("llm.probes is required for LLM checks")
        return load_probe_file(path)

    @cached_property
    def knowledge_base(self) -> str:
        path = self.spec.llm.get("knowledge_base")
        return Path(path).read_text(encoding="utf-8") if path else ""

    @cached_property
    def system_prompt(self) -> str:
        """System prompt sent when auditing a raw model (apps use their own)."""
        prompt = self.probes.get("system_prompt", "")
        if self.spec.llm.get("include_knowledge_base") and self.knowledge_base:
            prompt += "\n\nApproved product information:\n" + self.knowledge_base
        return prompt

    @cached_property
    def llm_transcript(self) -> list[dict[str, Any]]:
        """Every prompt/response exchanged during the audit, kept as evidence."""
        return []

    def llm_preflight(self) -> dict[str, Any]:
        """One harmless request before probing. Fails fast if the endpoint is down."""
        if self._preflight is not None:
            if isinstance(self._preflight, Exception):
                raise self._preflight
            return self._preflight
        if not self.llm_is_live:
            self._preflight = {"skipped": "replay mode"}
            return self._preflight
        result = self.llm_client.complete(
            self.system_prompt, "Hello. Please reply with one short sentence."
        )
        if not result.ok:
            label = self.llm_client.describe().get("endpoint", "the endpoint")
            self._preflight = EndpointUnavailable(
                f"Cannot reach the system under audit at {label}: {result.error}. "
                "Is the server running? Try `pramana ping <spec>`."
            )
            raise self._preflight
        self._preflight = {"latency_ms": result.latency_ms, "model": result.model}
        return self._preflight

    def ask_all(self, category: str, probes: list[dict[str, Any]]) -> list[list[Completion]]:
        """Send every probe ``samples`` times. Returns completions per probe, in order."""
        self.llm_preflight()
        jobs = [(i, s) for i in range(len(probes)) for s in range(self.llm_samples)]
        results: dict[tuple[int, int], Completion] = {}
        workers = max(1, int(self.spec.llm.get("concurrency", 1)))

        def run(job: tuple[int, int]) -> tuple[tuple[int, int], Completion]:
            i, s = job
            return job, self.llm_client.complete(self.system_prompt, probes[i]["prompt"], sample=s)

        if workers == 1:
            for job in jobs:
                key, completion = run(job)
                results[key] = completion
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for key, completion in pool.map(run, jobs):
                    results[key] = completion

        out: list[list[Completion]] = []
        for i, probe in enumerate(probes):
            runs = [results[(i, s)] for s in range(self.llm_samples)]
            for s, completion in enumerate(runs):
                self.llm_transcript.append(
                    {
                        "category": category,
                        "probe_id": probe["id"],
                        "sample": s,
                        "prompt": probe["prompt"],
                        "response": completion.text,
                        **{
                            k: v
                            for k, v in completion.to_dict().items()
                            if k
                            in (
                                "latency_ms",
                                "model",
                                "error",
                                "attempts",
                                "finish_reason",
                                "raw_text",
                            )
                        },
                    }
                )
            out.append(runs)
        return out

    def replay_records(self) -> list[dict[str, Any]]:
        """Transcript regrouped in replay format, so a live audit can be re-run offline."""
        grouped: dict[str, dict[str, Any]] = {}
        for entry in self.llm_transcript:
            if entry.get("error"):
                continue
            record = grouped.setdefault(
                entry["prompt"],
                {
                    "prompt": entry["prompt"],
                    "responses": [],
                    "latencies_ms": [],
                    "model": entry.get("model"),
                },
            )
            record["responses"].append(entry["response"])
            record["latencies_ms"].append(entry.get("latency_ms"))
        return list(grouped.values())

    def llm_run_summary(self) -> dict[str, Any]:
        if not self.spec.llm:
            return {}
        try:
            client = self.llm_client.describe()
        except Exception:  # noqa: BLE001
            client = {"mode": self.spec.llm.get("mode", "replay")}
        latencies = sorted(
            e["latency_ms"] for e in self.llm_transcript if e.get("latency_ms") is not None
        )
        models = sorted({e["model"] for e in self.llm_transcript if e.get("model")})
        errors = sum(1 for e in self.llm_transcript if e.get("error"))

        def pct(p: float) -> float | None:
            if not latencies:
                return None
            return latencies[min(len(latencies) - 1, int(round(p * (len(latencies) - 1))))]

        return {
            **client,
            "models_reported": models,
            "samples_per_probe": self.llm_samples,
            "calls": len(self.llm_transcript),
            "errors": errors,
            "latency_p50_ms": pct(0.5),
            "latency_p95_ms": pct(0.95),
            "probe_packs": self.probes.get("includes", []) if self.spec.llm.get("probes") else [],
        }

    # Agents ---------------------------------------------------------------

    @cached_property
    def agent_events(self) -> list[dict[str, Any]]:
        path = self.spec.agent.get("trace")
        if not path:
            raise MissingArtifact("agent.trace is required for agent checks")
        fmt = self.spec.agent.get("trace_format", "native")
        from pramana.adapters.traces import load_trace

        # A missing trace is "not applicable" (skip); a present-but-unreadable or
        # misconfigured trace is an error that blocks the gate — an audit cannot
        # vouch for evidence it could not parse.
        return load_trace(path, fmt)
