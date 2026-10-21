"""Clients for LLM applications under audit.

Three modes are supported:

* ``replay``: responses recorded from the system under audit are read from a
  JSONL file. Audits are reproducible and need no network, which suits CI.
* ``openai_compatible``: any server that implements ``/v1/chat/completions``
  (Ollama, vLLM, LM Studio, llama.cpp server, hosted providers, or your own app).
* ``http``: any JSON-over-HTTP endpoint, described by a request body template
  and the path to the answer in the response.

Every call returns a :class:`Completion` that carries latency, the model the
server reported and any error, so the audit can report service health as well
as behaviour. Transient failures (timeouts, connection resets, HTTP 429 and 5xx)
are retried with exponential backoff. A call that still fails is returned with
``error`` set rather than raised, so one bad request cannot end an audit.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}
ENV_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
REASONING_BLOCK = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)


@dataclass
class Completion:
    text: str
    latency_ms: float | None = None
    model: str | None = None
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    attempts: int = 1
    error: str | None = None
    raw_text: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, {}, "")}


class LLMClient(Protocol):
    name: str

    def complete(self, system: str, user: str, sample: int = 0) -> Completion: ...

    def describe(self) -> dict[str, Any]: ...


class EndpointUnavailable(RuntimeError):
    """Raised when the endpoint under audit cannot be reached at all."""


def strip_reasoning(text: str) -> str:
    """Remove <think>...</think> blocks that some reasoning models emit."""
    return REASONING_BLOCK.sub("", text).strip()


def expand_env(value: str) -> str:
    """Replace ${VAR} with the environment value, so secrets never sit in the spec."""
    return ENV_VAR.sub(lambda m: os.environ.get(m.group(1), ""), value)


def json_path(data: Any, path: str) -> Any:
    """Follow a dotted path such as ``choices.0.message.content``."""
    node = data
    for part in path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(path)
    return node


def _fill(template: Any, values: dict[str, Any]) -> Any:
    if isinstance(template, str):
        if template in {f"{{{k}}}" for k in values}:
            return values[template[1:-1]]
        out = template
        for key, val in values.items():
            out = out.replace(f"{{{key}}}", str(val))
        return expand_env(out)
    if isinstance(template, list):
        return [_fill(v, values) for v in template]
    if isinstance(template, dict):
        return {k: _fill(v, values) for k, v in template.items()}
    return template


def endpoint_label(url: str) -> str:
    """Scheme, host and port only: no paths, tokens or query strings in evidence."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}{':' + str(parsed.port) if parsed.port else ''}"


class ReplayClient:
    """Returns recorded responses keyed by the exact user prompt.

    Each JSONL line holds ``prompt`` and either ``response`` or ``responses``
    (one per sample). Repeated samples cycle through the recorded list.
    """

    name = "replay"

    def __init__(self, path: Path):
        self.path = Path(path)
        self._responses: dict[str, list[str]] = {}
        self._models: dict[str, str] = {}
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if "prompt" not in record or not ({"response", "responses"} & record.keys()):
                raise ValueError(f"{self.path.name}:{line_no} needs 'prompt' and 'response(s)'")
            responses = record.get("responses") or [record["response"]]
            self._responses[record["prompt"].strip()] = [str(r) for r in responses]
            if record.get("model"):
                self._models[record["prompt"].strip()] = record["model"]

    def complete(self, system: str, user: str, sample: int = 0) -> Completion:
        key = user.strip()
        if key not in self._responses:
            return Completion(text="", error=f"no recorded response for prompt: {key[:60]!r}")
        responses = self._responses[key]
        return Completion(text=responses[sample % len(responses)], model=self._models.get(key))

    def describe(self) -> dict[str, Any]:
        return {"mode": self.name, "source": self.path.name, "prompts": len(self._responses)}


class _HTTPBase:
    def __init__(
        self,
        *,
        timeout: float = 60.0,
        max_retries: int = 2,
        backoff: float = 1.0,
        headers: dict[str, str] | None = None,
    ):
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.backoff = float(backoff)
        self.headers = {k: expand_env(str(v)) for k, v in (headers or {}).items()}

    def _post(self, url: str, body: dict[str, Any], method: str = "POST") -> tuple[Any, float, int]:
        """POST JSON with retries. Returns (parsed JSON, latency ms of last attempt, attempts)."""
        payload = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json", **self.headers}
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 2):
            request = urllib.request.Request(url, data=payload, headers=headers, method=method)
            started = time.perf_counter()
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                    raw = response.read().decode("utf-8")
                latency = (time.perf_counter() - started) * 1000
                return json.loads(raw), latency, attempt
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:200]
                last_error = RuntimeError(f"HTTP {exc.code}: {detail}")
                if exc.code not in RETRYABLE_STATUS:
                    raise last_error from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                reason = getattr(exc, "reason", exc)
                last_error = RuntimeError(f"{type(reason).__name__}: {reason}")
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"endpoint did not return JSON: {exc}") from exc
            if attempt <= self.max_retries:
                time.sleep(self.backoff * (2 ** (attempt - 1)) * (1 + random.random() * 0.25))
        raise last_error or RuntimeError("request failed")


class OpenAICompatibleClient(_HTTPBase):
    """Chat-completions client using only the standard library."""

    name = "openai_compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = 512,
        seed: int | None = None,
        send_system_prompt: bool = True,
        **kwargs: Any,
    ):
        headers = dict(kwargs.pop("headers", {}) or {})
        if api_key_env and os.environ.get(api_key_env):
            headers["Authorization"] = f"Bearer {os.environ[api_key_env]}"
        super().__init__(headers=headers, **kwargs)
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.seed = seed
        self.send_system_prompt = send_system_prompt

    def complete(self, system: str, user: str, sample: int = 0) -> Completion:
        messages = [{"role": "user", "content": user}]
        if system and self.send_system_prompt:
            messages.insert(0, {"role": "system", "content": system})
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        if self.seed is not None:
            body["seed"] = self.seed + sample
        try:
            data, latency, attempts = self._post(f"{self.base_url}/chat/completions", body)
            choice = data["choices"][0]
            raw = choice["message"].get("content") or ""
            usage = data.get("usage") or {}
            return Completion(
                text=strip_reasoning(raw),
                raw_text=raw if raw != strip_reasoning(raw) else None,
                latency_ms=round(latency, 1),
                model=data.get("model"),
                finish_reason=choice.get("finish_reason"),
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                attempts=attempts,
            )
        except Exception as exc:  # noqa: BLE001 - recorded as evidence, not raised
            return Completion(text="", error=str(exc)[:300])

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.name,
            "endpoint": endpoint_label(self.base_url),
            "model_requested": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": self.seed,
            "sends_system_prompt": self.send_system_prompt,
            "timeout_s": self.timeout,
            "max_retries": self.max_retries,
        }


class HTTPJSONClient(_HTTPBase):
    """Generic JSON endpoint, e.g. ``POST /chat {"question": "..."} -> {"answer": "..."}``."""

    name = "http"

    def __init__(
        self,
        url: str,
        body: dict[str, Any],
        response_path: str,
        method: str = "POST",
        model_path: str | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.url = expand_env(url)
        self.body = body
        self.response_path = response_path
        self.model_path = model_path
        self.method = method.upper()

    def complete(self, system: str, user: str, sample: int = 0) -> Completion:
        body = _fill(self.body, {"prompt": user, "system": system, "sample": sample})
        try:
            data, latency, attempts = self._post(self.url, body, method=self.method)
            raw = str(json_path(data, self.response_path))
            model = None
            if self.model_path:
                try:
                    model = str(json_path(data, self.model_path))
                except (KeyError, IndexError, ValueError):
                    model = None
            return Completion(
                text=strip_reasoning(raw),
                latency_ms=round(latency, 1),
                model=model,
                attempts=attempts,
            )
        except (KeyError, IndexError, ValueError) as exc:
            return Completion(
                text="", error=f"response_path '{self.response_path}' not found: {exc}"
            )
        except Exception as exc:  # noqa: BLE001
            return Completion(text="", error=str(exc)[:300])

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.name,
            "endpoint": endpoint_label(self.url),
            "response_path": self.response_path,
            "timeout_s": self.timeout,
            "max_retries": self.max_retries,
        }


def build_client(config: dict[str, Any]) -> LLMClient:
    mode = config.get("mode", "replay")
    common = {k: config[k] for k in ("timeout", "max_retries", "backoff", "headers") if k in config}
    if mode == "replay":
        if not config.get("replay"):
            raise ValueError("llm.replay must point to a JSONL transcript file in replay mode")
        return ReplayClient(config["replay"])
    if mode == "openai_compatible":
        for key in ("base_url", "model"):
            if not config.get(key):
                raise ValueError(f"llm.{key} is required in openai_compatible mode")
        return OpenAICompatibleClient(
            base_url=expand_env(config["base_url"]),
            model=config["model"],
            api_key_env=config.get("api_key_env"),
            temperature=float(config.get("temperature", 0.0)),
            max_tokens=config.get("max_tokens", 512),
            seed=config.get("seed"),
            send_system_prompt=bool(config.get("send_system_prompt", True)),
            **common,
        )
    if mode == "http":
        for key in ("url", "body", "response_path"):
            if not config.get(key):
                raise ValueError(f"llm.{key} is required in http mode")
        return HTTPJSONClient(
            url=config["url"],
            body=config["body"],
            response_path=config["response_path"],
            method=config.get("method", "POST"),
            model_path=config.get("model_path"),
            **common,
        )
    raise ValueError(f"Unknown llm.mode '{mode}' (use replay, openai_compatible or http)")
