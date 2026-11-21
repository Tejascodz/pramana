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
import math
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
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
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

    def complete(
        self, system: str, user: str, sample: int = 0, headers: dict[str, str | None] | None = None
    ) -> Completion: ...

    def chat(self, system: str, messages: list[dict[str, str]], sample: int = 0) -> Completion:
        """Send a whole conversation (``role``/``content`` dicts, ending with a user turn)."""
        ...

    def describe(self) -> dict[str, Any]: ...


class EndpointUnavailable(RuntimeError):
    """Raised when the endpoint under audit cannot be reached at all."""


#: Separates the user turns of a conversation in replay keys.
TURN_SEPARATOR = "\n\u241e\n"


def conversation_key(messages: list[dict[str, str]]) -> str:
    """Replay key for a conversation: its user turns, in order.

    A single-turn conversation keys on the prompt itself, so recordings made before
    conversations were supported keep working.
    """
    users = [str(m.get("content", "")).strip() for m in messages if m.get("role") == "user"]
    return TURN_SEPARATOR.join(users)


def flatten_conversation(messages: list[dict[str, str]]) -> str:
    """A conversation as one prompt, for endpoints that accept a single message."""
    lines = []
    for m in messages[:-1]:
        who = "User" if m.get("role") == "user" else "Assistant"
        lines.append(f"{who}: {m.get('content', '')}")
    last = messages[-1].get("content", "") if messages else ""
    if not lines:
        return str(last)
    return "Conversation so far:\n" + "\n".join(lines) + f"\n\nUser: {last}"


def strip_reasoning(text: str) -> str:
    """Remove <think>...</think> blocks that some reasoning models emit."""
    return REASONING_BLOCK.sub("", text).strip()


def expand_env(value: str) -> str:
    """Replace ${VAR} with the environment value, so secrets never sit in the spec.

    Applied to request headers only. URLs and request bodies are sent exactly as
    written, so a spec cannot copy environment variables (keys, paths, tokens)
    into a request to an endpoint of its choosing.
    """
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
        return out
    if isinstance(template, list):
        return [_fill(v, values) for v in template]
    if isinstance(template, dict):
        return {k: _fill(v, values) for k, v in template.items()}
    return template


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
CREDENTIAL_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "api-key", "cookie"}


def check_endpoint(url: str, *, sends_credentials: bool) -> None:
    """Refuse endpoints that could read local files or leak credentials in transit.

    Only http and https are allowed (urllib would otherwise open file:// and ftp://
    URLs). Credentials are only sent over https, or to this computer.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"Endpoint must be an http(s) URL with a host, got {parsed.scheme or 'no'} scheme"
        )
    if parsed.username or parsed.password:
        raise ValueError("Put credentials in headers (from the environment), not in the URL")
    if sends_credentials and parsed.scheme != "https" and parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"Refusing to send credentials over plain HTTP to {endpoint_label(url)}. "
            "Use an https URL, or an endpoint on this computer."
        )


def endpoint_label(url: str) -> str:
    """Scheme, host and port only: no paths, tokens or query strings in evidence."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}{':' + str(parsed.port) if parsed.port else ''}"


#: Numeric LLM settings: (kind, lowest, highest, may be null). "count" is a whole number.
LLM_NUMBER_RULES: dict[str, tuple[str, float, float, bool]] = {
    "timeout": ("number", 0.0, 3600.0, False),
    "max_retries": ("count", 0, 20, False),
    "backoff": ("number", 0.0, 600.0, False),
    "samples": ("count", 1, 1000, False),
    "concurrency": ("count", 1, 64, False),
    "temperature": ("number", 0.0, 2.0, False),
    "max_tokens": ("count", 1, 1_000_000, True),
    "seed": ("count", 0, 2**63 - 1, True),
    "settle_ms": ("count", 0, 600_000, False),
    "obfuscation_budget": ("count", 1, 1_000_000, True),
}


def validate_llm_settings(config: dict[str, Any], where: str = "llm") -> None:
    """Refuse numeric settings that would silently change how many calls are made or how
    long they may take: booleans, text, NaN, infinities, negatives and fractions where a
    count is needed. ``timeout`` must also be above zero."""
    for key, (kind, low, high, nullable) in LLM_NUMBER_RULES.items():
        if key not in config:
            continue
        value = config[key]
        name = f"{where}.{key}"
        if value is None and nullable:
            continue
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"{name} must be a number, not {value!r}")
        if not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number, not {value!r}")
        if kind == "count" and value != int(value):
            raise ValueError(f"{name} must be a whole number, not {value!r}")
        if not low <= value <= high or (key == "timeout" and value <= 0):
            bound = "above 0" if key == "timeout" else f"at least {low:g}"
            raise ValueError(f"{name} must be {bound} and at most {high:g}, not {value!r}")


def _is_latency(value: Any) -> bool:
    return value is None or (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _record_error(source: str, where: str, problem: str) -> ValueError:
    return ValueError(f"{source}{where}: {problem}")


class ReplayClient:
    """Returns recorded responses keyed by the exact user prompt.

    Accepts either format Pramana writes into an audit pack:

    * ``llm_replay.jsonl``: one line per prompt with ``response`` or
      ``responses`` (one per sample) and optional ``latencies_ms``;
    * ``evidence/4-testing/llm_transcript.json``: the full transcript, one
      entry per call, including measured latency.

    Repeated samples cycle through the recorded list. Recorded latencies are
    returned with each response, so a re-scored audit keeps its service-health
    evidence.
    """

    name = "replay"

    def __init__(self, path: Path):
        self.path = Path(path)
        self._responses: dict[str, list[str]] = {}
        self._latencies: dict[str, list[float | None]] = {}
        self._models: dict[str, str] = {}
        try:
            text = self.path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{self.path.name} is not valid UTF-8 text") from exc
        if self.path.suffix == ".json":
            try:
                entries = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{self.path.name} is not valid JSON: {exc}") from exc
            self._load_transcript(entries)
        else:
            self._load_jsonl(text)

    def _add(self, prompt: str, response: str, latency: float | None, model: str | None) -> None:
        key = prompt.strip()
        self._responses.setdefault(key, []).append(str(response))
        self._latencies.setdefault(key, []).append(latency)
        if model:
            self._models[key] = model

    def _load_jsonl(self, text: str) -> None:
        """Every line is checked: a malformed or partial recording is refused, with the
        line number, rather than loaded in part (which would silently drop samples)."""
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            err = lambda problem: _record_error(self.path.name, f":{line_no}", problem)  # noqa: E731,B023
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise err(f"not valid JSON ({exc.msg})") from exc
            if not isinstance(record, dict):
                raise err(f"is a JSON {type(record).__name__}, expected an object")
            if "conversation" in record:
                turns = record["conversation"]
                if (
                    not isinstance(turns, list)
                    or not turns
                    or not all(isinstance(u, str) for u in turns)
                ):
                    raise err("'conversation' must be a non-empty list of user messages")
                prompt = TURN_SEPARATOR.join(u.strip() for u in turns)
            elif isinstance(record.get("prompt"), str):
                prompt = record["prompt"]
            else:
                raise err("needs a text 'prompt' (or a 'conversation')")
            if "responses" in record:
                responses = record["responses"]
                if not isinstance(responses, list) or not responses:
                    raise err("'responses' must be a non-empty list")
            elif "response" in record:
                responses = [record["response"]]
            else:
                raise err("needs 'response' or 'responses'")
            if not all(isinstance(r, str) for r in responses):
                raise err("every response must be text")
            latencies = record.get("latencies_ms")
            if latencies is None:
                latencies = [None] * len(responses)
            elif not isinstance(latencies, list) or len(latencies) != len(responses):
                raise err(
                    f"'latencies_ms' must list one value per response ({len(responses)} responses)"
                )
            elif not all(_is_latency(v) for v in latencies):
                raise err("every latency must be a non-negative number or null")
            model = record.get("model")
            if model is not None and not isinstance(model, str):
                raise err("'model' must be text")
            for response, latency in zip(responses, latencies, strict=True):
                self._add(prompt, response, latency, model)

    def _load_transcript(self, entries: Any) -> None:
        if not isinstance(entries, list):
            raise ValueError(f"{self.path.name} is not a transcript (expected a JSON list)")
        for i, entry in enumerate(entries, 1):
            err = lambda problem: _record_error(self.path.name, f" entry {i}", problem)  # noqa: E731,B023
            if not isinstance(entry, dict):
                raise err(f"is a JSON {type(entry).__name__}, expected an object")
            for key in ("prompt", "conversation_key", "response", "model"):
                if entry.get(key) is not None and not isinstance(entry[key], str):
                    raise err(f"'{key}' must be text")
            sample = entry.get("sample", 0)
            if isinstance(sample, bool) or not isinstance(sample, int):
                raise err("'sample' must be a whole number")
            if not _is_latency(entry.get("latency_ms")):
                raise err("'latency_ms' must be a non-negative number or null")
        usable = [e for e in entries if not e.get("error") and isinstance(e.get("prompt"), str)]
        for entry in sorted(usable, key=lambda e: (e["prompt"], e.get("sample", 0))):
            self._add(
                entry.get("conversation_key") or entry["prompt"],
                entry.get("response") or "",
                entry.get("latency_ms"),
                entry.get("model"),
            )

    def complete(
        self, system: str, user: str, sample: int = 0, headers: dict[str, str | None] | None = None
    ) -> Completion:
        # Keyed by prompt: an access-control probe's headers are part of its recorded run.
        key = user.strip()
        if key not in self._responses:
            return Completion(text="", error=f"no recorded response for prompt: {key[:60]!r}")
        responses = self._responses[key]
        i = sample % len(responses)
        return Completion(
            text=responses[i], model=self._models.get(key), latency_ms=self._latencies[key][i]
        )

    def chat(self, system: str, messages: list[dict[str, str]], sample: int = 0) -> Completion:
        return self.complete(system, conversation_key(messages), sample=sample)

    @property
    def has_conversations(self) -> bool:
        """True when the recording holds at least one multi-turn conversation."""
        return any(TURN_SEPARATOR in key for key in self._responses)

    @property
    def has_latency(self) -> bool:
        return any(v is not None for values in self._latencies.values() for v in values)

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.name,
            "source": self.path.name,
            "prompts": len(self._responses),
            "recorded_latency": self.has_latency,
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: urllib would otherwise resend headers, keys included, to the new host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect to {endpoint_label(newurl)} refused", headers, fp
        )


_OPENER = urllib.request.build_opener(_NoRedirect)


class _HTTPBase:
    def __init__(
        self,
        *,
        timeout: float = 60.0,
        max_retries: int = 2,
        backoff: float = 1.0,
        headers: dict[str, str] | None = None,
    ):
        validate_llm_settings({"timeout": timeout, "max_retries": max_retries, "backoff": backoff})
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.backoff = float(backoff)
        raw = {k: str(v) for k, v in (headers or {}).items()}
        self.headers = {k: expand_env(v) for k, v in raw.items()}
        self.sends_credentials = any(
            k.lower() in CREDENTIAL_HEADERS or ENV_VAR.search(v) for k, v in raw.items()
        )

    def _post(
        self,
        url: str,
        body: dict[str, Any],
        method: str = "POST",
        extra_headers: dict[str, str | None] | None = None,
    ) -> tuple[Any, float, int]:
        """POST JSON with retries. Returns (parsed JSON, latency ms of last attempt, attempts).

        ``extra_headers`` come from a probe (an access-control test claiming another identity).
        They are sent exactly as written, never expanded from the environment, and a value of
        None removes that header, for example to send a request without the configured token.
        """
        payload = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json", **self.headers}
        for name, value in (extra_headers or {}).items():
            for existing in [k for k in headers if k.lower() == name.lower()]:
                del headers[existing]
            if value is not None:
                headers[name] = str(value)
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 2):
            request = urllib.request.Request(url, data=payload, headers=headers, method=method)  # noqa: S310 - http(s) only, checked above
            started = time.perf_counter()
            try:
                # Scheme and host were checked by check_endpoint; redirects are refused.
                with _OPENER.open(request, timeout=self.timeout) as response:  # nosec B310
                    data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise RuntimeError(f"response larger than {MAX_RESPONSE_BYTES} bytes")
                try:
                    raw = data.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise RuntimeError("endpoint response is not valid UTF-8 text") from exc
                latency = (time.perf_counter() - started) * 1000
                return json.loads(raw), latency, attempt
            except urllib.error.HTTPError as exc:
                if 300 <= exc.code < 400:
                    detail = str(exc.msg)
                else:
                    body = exc.read(200) if exc.fp else b""
                    detail = body.decode("utf-8", errors="replace") or str(exc.msg)
                last_error = RuntimeError(f"HTTP {exc.code}: {detail}")
                if exc.code not in RETRYABLE_STATUS:
                    raise last_error from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                reason = getattr(exc, "reason", exc)
                last_error = RuntimeError(f"{type(reason).__name__}: {reason}")
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"endpoint did not return JSON: {exc}") from exc
            if attempt <= self.max_retries:
                jitter = 1 + random.random() * 0.25  # noqa: S311  # nosec B311 - retry jitter, not security
                time.sleep(self.backoff * (2 ** (attempt - 1)) * jitter)
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
        check_endpoint(self.base_url, sends_credentials=self.sends_credentials)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.seed = seed
        self.send_system_prompt = send_system_prompt

    def complete(
        self, system: str, user: str, sample: int = 0, headers: dict[str, str | None] | None = None
    ) -> Completion:
        return self.chat(
            system, [{"role": "user", "content": user}], sample=sample, headers=headers
        )

    def chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        sample: int = 0,
        headers: dict[str, str | None] | None = None,
    ) -> Completion:
        messages = [{"role": m["role"], "content": m["content"]} for m in messages]
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
            data, latency, attempts = self._post(
                f"{self.base_url}/chat/completions", body, extra_headers=headers
            )
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

    def chat_tools(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        sample: int = 0,
    ) -> Completion:
        """One step of native function calling (the OpenAI ``tools`` interface).

        The reply's tool calls are returned in ``extra["tool_calls"]`` as
        ``{"id", "name", "arguments"}`` (arguments parsed from JSON when possible), and
        the raw assistant message in ``extra["message"]`` so it can go back in history.
        """
        msgs = list(messages)
        if system and self.send_system_prompt:
            msgs.insert(0, {"role": "system", "content": system})
        body: dict[str, Any] = {
            "model": self.model,
            "messages": msgs,
            "tools": tools,
            "temperature": self.temperature,
        }
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        if self.seed is not None:
            body["seed"] = self.seed + sample
        try:
            data, latency, attempts = self._post(f"{self.base_url}/chat/completions", body)
            choice = data["choices"][0]
            message = choice["message"]
            calls = []
            for i, call in enumerate(message.get("tool_calls") or []):
                fn = call.get("function") or {}
                raw_args = fn.get("arguments") or {}
                if isinstance(raw_args, str):
                    try:
                        raw_args = json.loads(raw_args) if raw_args.strip() else {}
                    except json.JSONDecodeError:
                        raw_args = {"_unparsed": raw_args}
                calls.append(
                    {
                        "id": call.get("id") or f"call_{i}",
                        "name": str(fn.get("name", "")),
                        "arguments": raw_args if isinstance(raw_args, dict) else {},
                    }
                )
            raw = message.get("content") or ""
            return Completion(
                text=strip_reasoning(raw),
                latency_ms=round(latency, 1),
                model=data.get("model"),
                finish_reason=choice.get("finish_reason"),
                attempts=attempts,
                extra={"tool_calls": calls, "message": message},
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
        self.url = url
        check_endpoint(self.url, sends_credentials=self.sends_credentials)
        self.body = body
        self.response_path = response_path
        self.model_path = model_path
        self.method = method.upper()

    @property
    def native_history(self) -> bool:
        """True when the body template has a ``{messages}`` slot for the whole conversation."""
        return "{messages}" in json.dumps(self.body)

    def complete(
        self, system: str, user: str, sample: int = 0, headers: dict[str, str | None] | None = None
    ) -> Completion:
        return self.chat(
            system, [{"role": "user", "content": user}], sample=sample, headers=headers
        )

    def chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        sample: int = 0,
        headers: dict[str, str | None] | None = None,
    ) -> Completion:
        last = str(messages[-1]["content"]) if messages else ""
        values: dict[str, Any] = {"system": system, "sample": sample}
        if self.native_history:
            values.update(messages=[dict(m) for m in messages], prompt=last)
        else:
            values["prompt"] = flatten_conversation(messages)
        body = _fill(self.body, values)
        try:
            data, latency, attempts = self._post(
                self.url, body, method=self.method, extra_headers=headers
            )
        except Exception as exc:  # noqa: BLE001 - transport, HTTP or decoding: recorded as evidence
            return Completion(text="", error=str(exc)[:300])
        try:
            raw = str(json_path(data, self.response_path))
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            return Completion(
                text="", error=f"response_path '{self.response_path}' not found: {exc}"
            )
        model = None
        if self.model_path:
            try:
                model = str(json_path(data, self.model_path))
            except (KeyError, IndexError, ValueError, TypeError):
                model = None
        return Completion(
            text=strip_reasoning(raw),
            latency_ms=round(latency, 1),
            model=model,
            attempts=attempts,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.name,
            "endpoint": endpoint_label(self.url),
            "response_path": self.response_path,
            "conversation_history": "native" if self.native_history else "flattened",
            "timeout_s": self.timeout,
            "max_retries": self.max_retries,
        }


def build_client(config: dict[str, Any]) -> LLMClient:
    validate_llm_settings(config)
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
            base_url=config["base_url"],
            model=config["model"],
            api_key_env=config.get("api_key_env"),
            temperature=float(config.get("temperature", 0.0)),
            max_tokens=config.get("max_tokens", 512),
            seed=config.get("seed"),
            send_system_prompt=bool(config.get("send_system_prompt", True)),
            **common,
        )
    if mode == "browser":
        for key in ("url", "input_selector", "reply_selector"):
            if not config.get(key):
                raise ValueError(f"llm.{key} is required in browser mode")
        if int(config.get("concurrency", 1)) > 1:
            raise ValueError("browser mode drives one page at a time: remove llm.concurrency")
        from pramana.adapters.browser import BrowserChatClient

        return BrowserChatClient(
            url=config["url"],
            input_selector=config["input_selector"],
            reply_selector=config["reply_selector"],
            send_selector=config.get("send_selector"),
            timeout=float(config.get("timeout", 60.0)),
            settle_ms=int(config.get("settle_ms", 1200)),
            headless=bool(config.get("headless", True)),
            sandbox=config.get("browser_sandbox", True) is not False,
        )
    if mode == "http":
        for key in ("url", "body", "response_path"):
            if not config.get(key):
                raise ValueError(f"llm.{key} is required in http mode")
        method = str(config.get("method", "POST")).upper()
        if method not in ("POST", "PUT", "PATCH"):
            # The prompt travels in the JSON body; a GET or HEAD would not carry it reliably.
            raise ValueError(f"llm.method must be POST, PUT or PATCH in http mode, not {method}")
        return HTTPJSONClient(
            url=config["url"],
            body=config["body"],
            response_path=config["response_path"],
            method=method,
            model_path=config.get("model_path"),
            **common,
        )
    raise ValueError(f"Unknown llm.mode '{mode}' (use replay, openai_compatible, http or browser)")
