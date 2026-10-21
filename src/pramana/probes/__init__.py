"""Probe files and the built-in probe library.

A probe file is YAML with an optional ``canary``, a ``system_prompt`` (used
only when auditing a raw model), ``probes`` grouped by category, and an
optional ``include`` list that pulls in other probe files. Built-in packs are
referenced as ``builtin:<name>``; anything else is a path relative to the file.

``{canary}`` anywhere in a probe is replaced with the canary value, so the
same pack works for every deployment.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml

CATEGORIES = ("prompt_injection", "sensitive_disclosure", "groundedness", "policy")


class ProbeFileError(ValueError):
    """Raised when a probe file is malformed."""


def builtin_packs() -> list[str]:
    root = resources.files("pramana.probes").joinpath("packs")
    return sorted(p.name[:-5] for p in root.iterdir() if p.name.endswith(".yaml"))


def _read_builtin(name: str) -> dict[str, Any]:
    root = resources.files("pramana.probes").joinpath("packs")
    target = root.joinpath(f"{name}.yaml")
    if not target.is_file():
        raise ProbeFileError(
            f"Unknown built-in probe pack '{name}'. Available: {', '.join(builtin_packs())}"
        )
    return yaml.safe_load(target.read_text(encoding="utf-8")) or {}


def _merge(into: dict[str, list], data: dict[str, Any], source: str) -> None:
    for category, items in (data.get("probes") or {}).items():
        if category not in CATEGORIES:
            raise ProbeFileError(f"{source}: unknown probe category '{category}'")
        for item in items or []:
            if "id" not in item or "prompt" not in item:
                raise ProbeFileError(f"{source}: every probe needs 'id' and 'prompt'")
            entry = dict(item)
            entry.setdefault("source", source)
            into.setdefault(category, []).append(entry)


def _fill(value: Any, canary: str) -> Any:
    if isinstance(value, str):
        return value.replace("{canary}", canary)
    if isinstance(value, list):
        return [_fill(v, canary) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, canary) for k, v in value.items()}
    return value


def load_probe_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    probes: dict[str, list] = {}
    sources = []
    for ref in data.get("include", []) or []:
        if str(ref).startswith("builtin:"):
            name = str(ref).split(":", 1)[1]
            _merge(probes, _read_builtin(name), f"builtin:{name}")
        else:
            included = path.parent / ref
            _merge(
                probes, yaml.safe_load(included.read_text(encoding="utf-8")) or {}, included.name
            )
        sources.append(str(ref))
    _merge(probes, data, path.name)

    seen: set[str] = set()
    for items in probes.values():
        for item in items:
            if item["id"] in seen:
                raise ProbeFileError(f"Duplicate probe id '{item['id']}'")
            seen.add(item["id"])

    canary = str(data.get("canary", ""))
    return {
        "canary": canary,
        "system_prompt": _fill(data.get("system_prompt", ""), canary),
        "probes": _fill(probes, canary),
        "includes": sources,
    }
