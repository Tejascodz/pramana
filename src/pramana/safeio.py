"""Defensive input and output helpers.

Pramana reads files written by other people (specs, probe packs, model cards,
traces, CSVs) and writes files that other people open (CSV exports, HTML). The
helpers here apply the same limits everywhere:

* ``load_yaml`` refuses oversized files and parses with a ``yaml.SafeLoader``, which
  never constructs Python objects, and refuses a mapping that repeats a key.
* ``csv_safe`` neutralises spreadsheet formulas, so text taken from a model's answer
  or a trace cannot run as a formula when a reviewer opens a CSV in Excel, Numbers
  or Google Sheets (CWE-1236, "CSV injection").
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any

import yaml

#: Largest YAML configuration file Pramana will parse (specs, probe packs, model cards).
MAX_YAML_BYTES = int(os.environ.get("PRAMANA_MAX_YAML_BYTES", 5 * 1024 * 1024))


class InputTooLarge(ValueError):
    """A file is larger than Pramana is willing to read into memory."""


def read_text_limited(path: str | Path, max_bytes: int) -> str:
    path = Path(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise InputTooLarge(
            f"{path.name} is {size:,} bytes, above the {max_bytes:,}-byte limit; "
            "refusing to read it"
        )
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:  # the file grew after stat()
        raise InputTooLarge(f"{path.name} is above the {max_bytes:,}-byte limit")
    return data.decode("utf-8")


class DuplicateKeyError(yaml.constructor.ConstructorError):
    """A YAML mapping repeats a key. Plain YAML keeps the last value silently, so a second
    ``gate:`` or ``thresholds:`` section would quietly replace the first."""


class _StrictLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` that refuses a mapping with the same key twice."""

    def construct_mapping(self, node, deep=False):  # noqa: ANN001
        if isinstance(node, yaml.MappingNode):
            seen: dict[Any, Any] = {}
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    continue  # "<<: *defaults" may be overridden by explicit keys
                key = self.construct_object(key_node, deep=True)
                try:
                    hash(key)
                except TypeError:
                    continue  # the base class reports unhashable keys
                if key in seen:
                    raise DuplicateKeyError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {key!r} (first at line {seen[key].line + 1})",
                        key_node.start_mark,
                    )
                seen[key] = key_node.start_mark
        return super().construct_mapping(node, deep=deep)


def parse_yaml(text: str) -> Any:
    """Parse YAML text: no Python objects (a ``SafeLoader``), no repeated keys."""
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506  # nosec B506 - SafeLoader subclass


def load_yaml(path: str | Path, max_bytes: int | None = None) -> Any:
    """Parse a YAML file safely: size-capped, no Python objects, no repeated keys."""
    return parse_yaml(read_text_limited(path, max_bytes or MAX_YAML_BYTES))


_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠")
_PLAIN_NUMBER = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?%?$")


def csv_safe(value: Any) -> Any:
    """Return ``value`` so a spreadsheet shows it as text, never runs it as a formula.

    Strings that start with a formula trigger get a leading apostrophe, the
    convention spreadsheets use for literal text. Plain numbers such as ``-0.25``
    are left alone so exports stay usable.
    """
    if not isinstance(value, str) or not value:
        return value
    if value.startswith(_FORMULA_START) and not _PLAIN_NUMBER.match(value):
        return "'" + value
    return value


def strict_json(value: Any) -> Any:
    """``value`` with NaN and infinities replaced by null, so the file is standard JSON
    that jq, JavaScript and other strict parsers can read."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: strict_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [strict_json(v) for v in value]
    return value
