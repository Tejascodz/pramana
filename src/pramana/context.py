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

from pramana.adapters.llm import (
    Completion,
    EndpointUnavailable,
    LLMClient,
    build_client,
    conversation_key,
)
from pramana.probes import load_probe_file
from pramana.safeio import load_yaml
from pramana.spec import AuditSpec


class MissingArtifact(RuntimeError):
    """Raised by a check when an artifact it needs was not supplied (not applicable)."""


class DeclaredInputMissing(RuntimeError):
    """The spec names an input that does not exist.

    Unlike an input that was never supplied, this makes the audit incomplete: the
    check is reported as an error, so the gate blocks instead of passing a system
    whose tests could not run.
    """


class CannotMeasure(RuntimeError):
    """The data cannot support this measurement (one outcome class, missing scores...).

    Reported as "Not tested", which makes the audit incomplete and blocks the gate. A
    metric that cannot be computed must never fall through to a pass (an undefined AUC
    compares false with every threshold).
    """


#: Label given to rows whose protected attribute is missing, so they stay visible as a
#: group in fairness results instead of being dropped or breaking the comparison.
MISSING_GROUP = "(missing)"


def require_file(path: Path, what: str) -> Path:
    if not path.exists():
        raise DeclaredInputMissing(
            f"{what} is declared in the spec but not found: {path}. Create it or fix the path."
        )
    return path


#: Module prefixes whose types a .skops model may contain. skops rebuilds objects from
#: these modules without unpickling, so arbitrary code in the file never runs.
SKOPS_TRUSTED_PREFIXES = ("sklearn.", "numpy.", "scipy.", "builtins.", "collections.")


def _load_skops(path: Path) -> Any:
    try:
        from skops.io import get_untrusted_types, load
    except ImportError as exc:  # pragma: no cover - depends on the optional extra
        raise MissingArtifact(
            'Loading a .skops model needs skops: pip install "pramana-audit[skops]"'
        ) from exc
    untrusted = get_untrusted_types(file=path)
    refused = [t for t in untrusted if not t.startswith(SKOPS_TRUSTED_PREFIXES)]
    if refused:
        raise MissingArtifact(
            f"{path.name} contains types outside scikit-learn, NumPy and SciPy, which "
            f"Pramana will not load: {', '.join(sorted(refused))}"
        )
    return load(path, trusted=untrusted)


class AuditContext:
    def __init__(self, spec: AuditSpec, audit_date: date | None = None):
        self.spec = spec
        self.audit_date = audit_date or date.today()
        self.rng = np.random.default_rng(spec.seed)
        self._preflight: dict[str, Any] | Exception | None = None
        # Results one check publishes for a later one (e.g. plain injection verdicts
        # that the obfuscation check compares against).
        self.shared: dict[str, Any] = {}
        self._sandbox_error: Exception | None = None

    # Tabular artifacts ---------------------------------------------------

    def _read_table(self, key: str) -> pd.DataFrame | None:
        path = self.spec.artifact(key)
        if path is None:
            return None
        require_file(path, f"artifacts.{key}")
        if path.suffix.lower() == ".parquet":
            df = pd.read_parquet(path)
        else:
            df = pd.read_csv(path)
        for col in self.spec.sensitive_features:
            if col in df.columns:
                df[col] = df[col].where(df[col].notna(), MISSING_GROUP).astype(str)
        return df

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
        require_file(path, "artifacts.model")
        self.spec.verify_artifact("model")
        if path.suffix.lower() == ".skops":
            return _load_skops(path)
        # Pickle (joblib) can execute code while loading. check_model_trust() refuses a
        # pickle that is neither pinned by SHA-256 nor explicitly trusted.
        self.spec.check_model_trust()
        return joblib.load(path)  # nosec B301 - pinned or explicitly trusted above

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
        missing = int(df[self.spec.target].isna().sum())
        if missing:
            # A missing label would otherwise count as a negative outcome and skew every metric.
            raise CannotMeasure(
                f"target column '{self.spec.target}' has {missing} missing label(s); remove or "
                "label those rows"
            )
        return (df[self.spec.target] == self.spec.positive_label).astype(int).to_numpy()

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Probability of the positive class for each row."""
        if not self.has_model:
            if self.spec.score_column and self.spec.score_column in df.columns:
                scores = df[self.spec.score_column].to_numpy(dtype=float)
                missing = int(np.isnan(scores).sum())
                if missing:
                    raise CannotMeasure(
                        f"score_column '{self.spec.score_column}' has {missing} missing value(s)"
                    )
                return scores
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
        if path is None:
            return None
        require_file(path, "artifacts.documentation")
        return load_yaml(path) or {}

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
        require_file(Path(path), "llm.probes")
        return load_probe_file(path)

    @cached_property
    def knowledge_base(self) -> str:
        path = self.spec.llm.get("knowledge_base")
        return (
            require_file(Path(path), "llm.knowledge_base").read_text(encoding="utf-8")
            if path
            else ""
        )

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
            extra = probes[i].get("headers")
            if extra:  # an access-control probe sends its own identity headers
                return job, self.llm_client.complete(
                    self.system_prompt, probes[i]["prompt"], sample=s, headers=extra
                )
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

    def converse_all(
        self, category: str, probes: list[dict[str, Any]]
    ) -> list[list[list[Completion]]]:
        """Play every multi-turn probe ``samples`` times, keeping the real replies in history.

        Returns, per probe and per sample, the completion for each user turn. A turn
        that fails ends that conversation (later turns would have no history to build on).
        """
        self.llm_preflight()
        jobs = [(i, s) for i in range(len(probes)) for s in range(self.llm_samples)]
        workers = max(1, int(self.spec.llm.get("concurrency", 1)))

        def run(job: tuple[int, int]) -> tuple[tuple[int, int], list[Completion]]:
            i, s = job
            history: list[dict[str, str]] = []
            replies: list[Completion] = []
            for turn in probes[i]["turns"]:
                history.append({"role": "user", "content": turn})
                completion = self.llm_client.chat(self.system_prompt, history, sample=s)
                replies.append(completion)
                if not completion.ok:
                    break
                history.append({"role": "assistant", "content": completion.text})
            return job, replies

        results: dict[tuple[int, int], list[Completion]] = {}
        if workers == 1:
            for job in jobs:
                key, replies = run(job)
                results[key] = replies
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for key, replies in pool.map(run, jobs):
                    results[key] = replies

        out: list[list[list[Completion]]] = []
        for i, probe in enumerate(probes):
            per_sample = [results[(i, s)] for s in range(self.llm_samples)]
            for s, replies in enumerate(per_sample):
                for t, completion in enumerate(replies):
                    users = probe["turns"][: t + 1]
                    self.llm_transcript.append(
                        {
                            "category": category,
                            "probe_id": probe["id"],
                            "sample": s,
                            "turn": t + 1,
                            "prompt": probe["turns"][t],
                            "conversation": list(users),
                            "conversation_key": conversation_key(
                                [{"role": "user", "content": u} for u in users]
                            ),
                            "response": completion.text,
                            **{
                                k: v
                                for k, v in completion.to_dict().items()
                                if k
                                in ("latency_ms", "model", "error", "attempts", "finish_reason")
                            },
                        }
                    )
            out.append(per_sample)
        return out

    def replay_records(self) -> list[dict[str, Any]]:
        """Transcript regrouped in replay format, so a live audit can be re-run offline."""
        grouped: dict[str, dict[str, Any]] = {}
        for entry in self.llm_transcript:
            if entry.get("error"):
                continue
            key = entry.get("conversation_key") or entry["prompt"]
            first = (
                {"conversation": entry["conversation"]}
                if entry.get("conversation") and len(entry["conversation"]) > 1
                else {"prompt": entry["prompt"]}
            )
            record = grouped.setdefault(
                key,
                {**first, "responses": [], "latencies_ms": [], "model": entry.get("model")},
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
    def scenarios(self) -> list[dict[str, Any]]:
        source = self.spec.agent.get("scenarios")
        if not source:
            raise MissingArtifact("agent.scenarios (or agent.sandbox) is needed for honeypot tests")
        from pramana.sandbox import load_scenarios

        return load_scenarios(source)

    @cached_property
    def sandbox_events(self) -> list[dict[str, Any]]:
        """Run the agent under audit through every scenario (live), once per audit."""
        from pramana.sandbox import run_sandbox

        if isinstance(self._sandbox_error, Exception):  # fail once, not once per check
            raise self._sandbox_error
        config = dict(self.spec.agent["sandbox"])
        client = build_client(config)
        probe = client.complete("You are a test.", "Reply with one short sentence.")
        if not probe.ok:
            label = client.describe().get("endpoint", "the endpoint")
            self._sandbox_error = EndpointUnavailable(
                f"Cannot reach the agent's model at {label}: {probe.error}"
            )
            raise self._sandbox_error
        return run_sandbox(
            client,
            self.scenarios,
            runs=max(1, int(config.get("runs", 1))),
            max_steps=max(1, int(config.get("max_steps", 8))),
            policy=str(config.get("system_prompt", "")),
            protocol=str(config.get("protocol", "tools")),
            approver=str(config.get("approver", "deny")),
        )

    @cached_property
    def agent_events(self) -> list[dict[str, Any]]:
        if self.spec.agent.get("sandbox"):
            return self.sandbox_events
        path = self.spec.agent.get("trace")
        if not path:
            raise MissingArtifact("agent.trace or agent.sandbox is required for agent checks")
        require_file(Path(path), "agent.trace")
        fmt = self.spec.agent.get("trace_format", "native")
        from pramana.adapters.traces import load_trace

        # No trace declared is "not applicable" (skip). A declared trace that is
        # missing, unreadable, misconfigured or empty is an error that blocks the gate:
        # an audit cannot vouch for evidence it could not read.
        events = load_trace(path, fmt)
        if not events:
            raise CannotMeasure(f"agent.trace {Path(path).name} contains no events")
        return events
