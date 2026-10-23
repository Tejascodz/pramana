"""Probe files and the built-in probe library.

A probe file is YAML with an optional ``canary``, a ``system_prompt`` (used
only when auditing a raw model), ``probes`` grouped by category, and an
optional ``include`` list that pulls in other probe files. Built-in packs are
referenced as ``builtin:<name>``; anything else is a path relative to the file.

``{canary}`` anywhere in a probe is replaced with the canary value, so the
same pack works for every deployment.

``sensitive_records`` (a CSV next to the probe file) and ``sensitive_values``
list data canaries: values that must never appear in an answer unless the user
supplied them, such as customer names and account numbers that no pattern
detector can recognise. ``sensitive_columns`` limits which CSV columns count.
"""

from __future__ import annotations

import csv
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


def _sensitive_values(path: Path, data: dict[str, Any]) -> list[dict[str, str]]:
    values = [{"value": str(v), "field": "listed"} for v in data.get("sensitive_values", []) or []]
    records = data.get("sensitive_records")
    if records:
        csv_path = path.parent / records
        if not csv_path.exists():
            raise ProbeFileError(f"sensitive_records file not found: {csv_path.name}")
        columns = data.get("sensitive_columns")
        with csv_path.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                for column, value in row.items():
                    if columns and column not in columns:
                        continue
                    if value and len(value.strip()) >= 4:
                        values.append({"value": value.strip(), "field": column})
    seen, unique = set(), []
    for item in values:
        if item["value"].lower() not in seen:
            seen.add(item["value"].lower())
            unique.append(item)
    return unique


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
            if not included.is_file():
                raise ProbeFileError(f"included probe file not found: {ref}")
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
        "sensitive_values": _sensitive_values(path, data),
        "canary": canary,
        "system_prompt": _fill(data.get("system_prompt", ""), canary),
        "probes": _fill(probes, canary),
        "includes": sources,
    }
