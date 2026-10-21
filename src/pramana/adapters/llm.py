"""Clients for LLM applications under audit.

Two modes are supported:

* ``replay``: responses recorded from the system under audit are read from a
  JSONL file. This is how most audits run in practice (the auditee supplies
  transcripts from a test environment) and keeps results reproducible in CI.
* ``openai_compatible``: live calls to any server that implements the
  ``/v1/chat/completions`` API (vLLM, Ollama, LM Studio, hosted providers).
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Protocol


class LLMClient(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


class ReplayClient:
    """Looks up the recorded response for an exact user prompt."""

    name = "replay"

    def __init__(self, path: Path):
        self.path = Path(path)
        self._responses: dict[str, str] = {}
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if "prompt" not in record or "response" not in record:
                raise ValueError(f"{self.path}:{line_no} needs 'prompt' and 'response' keys")
            self._responses[record["prompt"].strip()] = record["response"]

    def complete(self, system: str, user: str) -> str:
        key = user.strip()
        if key not in self._responses:
            raise KeyError(f"No recorded response for prompt: {key[:80]!r}")
        return self._responses[key]


class OpenAICompatibleClient:
    """Minimal chat-completions client using only the standard library."""

    name = "openai_compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str | None = None,
        timeout: float = 60.0,
        temperature: float = 0.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else ""
        self.timeout = timeout
        self.temperature = temperature

    def complete(self, system: str, user: str) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "temperature": self.temperature,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body, headers=headers, method="POST"
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]


def build_client(config: dict) -> LLMClient:
    mode = config.get("mode", "replay")
    if mode == "replay":
        if not config.get("replay"):
            raise ValueError("llm.replay must point to a JSONL transcript file in replay mode")
        return ReplayClient(config["replay"])
    if mode == "openai_compatible":
        return OpenAICompatibleClient(
            base_url=config["base_url"],
            model=config["model"],
            api_key_env=config.get("api_key_env"),
        )
    raise ValueError(f"Unknown llm.mode '{mode}'")
