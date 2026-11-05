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
import json
import re
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from pramana.safeio import load_yaml

CATEGORIES = (
    "prompt_injection",
    "sensitive_disclosure",
    "groundedness",
    "policy",
    "multi_turn",
    "access_control",
)


class ProbeFileError(ValueError):
    """Raised when a probe file is malformed."""


def builtin_packs() -> list[str]:
    root = resources.files("pramana.probes").joinpath("packs")
    return sorted(p.name[:-5] for p in root.iterdir() if p.name.endswith(".yaml"))


def _read_builtin(name: str) -> dict[str, Any]:
    root = resources.files("pramana.probes").joinpath("packs")
    # Only names from the shipped library: "builtin:../../x" must not reach other files.
    if name not in builtin_packs():
        raise ProbeFileError(
            f"Unknown built-in probe pack '{name}'. Available: {', '.join(builtin_packs())}"
        )
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
            if category == "multi_turn":
                turns = item.get("turns")
                if "id" not in item or not isinstance(turns, list) or len(turns) < 2:
                    raise ProbeFileError(
                        f"{source}: every multi_turn probe needs 'id' and at least two 'turns'"
                    )
                if not all(isinstance(turn, str) and turn.strip() for turn in turns):
                    raise ProbeFileError(f"{source}: {item['id']} has an empty or non-text turn")
                first = item.get("judge_from_turn", 1)
                if not isinstance(first, int) or not 1 <= first <= len(turns):
                    raise ProbeFileError(
                        f"{source}: {item['id']} judge_from_turn must be a turn number "
                        f"from 1 to {len(turns)}"
                    )
            elif "id" not in item or "prompt" not in item:
                raise ProbeFileError(f"{source}: every probe needs 'id' and 'prompt'")
            elif not isinstance(item["prompt"], str) or not item["prompt"].strip():
                raise ProbeFileError(f"{source}: {item['id']} has an empty or non-text prompt")
            if category == "access_control":
                _check_access_probe(item, source)
            # A bad pattern would otherwise fail only after every call had been made and paid for.
            for pattern in item.get("success_regex") or []:
                try:
                    re.compile(pattern)
                except (re.error, TypeError) as exc:
                    raise ProbeFileError(
                        f"{source}: {item['id']} success_regex {pattern!r} is not valid: {exc}"
                    ) from exc
            entry = dict(item)
            entry.setdefault("source", source)
            into.setdefault(category, []).append(entry)


def _check_access_probe(item: dict[str, Any], source: str) -> None:
    """An access-control probe claims an identity and names data that must not come back."""
    headers = item.get("headers") or {}
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and (v is None or isinstance(v, str)) for k, v in headers.items()
    ):
        raise ProbeFileError(f"{source}: {item['id']} headers must map names to text (or null)")
    if any("\r" in f"{k}{v}" or "\n" in f"{k}{v}" for k, v in headers.items()):
        raise ProbeFileError(f"{source}: {item['id']} headers must not contain line breaks")
    if not (item.get("must_not_include") or item.get("forbidden_record")):
        raise ProbeFileError(
            f"{source}: {item['id']} needs must_not_include or forbidden_record: the data that "
            "must not be returned to this caller"
        )


def _sensitive_rows(path: Path, data: dict[str, Any]) -> list[dict[str, str]]:
    """Whole records from ``sensitive_records``, for probes that name one (forbidden_record)."""
    records = data.get("sensitive_records")
    if not records:
        return []
    with (path.parent / records).open(encoding="utf-8") as handle:
        return [{k: (v or "").strip() for k, v in row.items()} for row in csv.DictReader(handle)]


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
    data = load_yaml(path) or {}
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
            included_data = load_yaml(included) or {}
            if included_data.get("include"):
                raise ProbeFileError(
                    f"{included.name} has its own 'include'; list every file in {path.name} "
                    "instead (includes are one level deep)"
                )
            _merge(probes, included_data, included.name)
        sources.append(str(ref))
    _merge(probes, data, path.name)

    seen: set[str] = set()
    for items in probes.values():
        for item in items:
            if item["id"] in seen:
                raise ProbeFileError(f"Duplicate probe id '{item['id']}'")
            seen.add(item["id"])

    canary = str(data.get("canary", "") or "")
    # Without a canary "{canary}" would become an empty marker, and a probe that looks for
    # nothing can never fail.
    if not canary and "{canary}" in json.dumps([probes, data.get("system_prompt", "")]):
        raise ProbeFileError(
            f"{path.name}: probes use {{canary}} but no 'canary' value is set in this file"
        )
    return {
        "sensitive_values": _sensitive_values(path, data),
        "sensitive_rows": _sensitive_rows(path, data),
        "canary": canary,
        "system_prompt": _fill(data.get("system_prompt", ""), canary),
        "probes": _fill(probes, canary),
        "includes": sources,
    }
