"""Defensive input and output helpers.

Pramana reads files written by other people (specs, probe packs, model cards,
traces, CSVs) and writes files that other people open (CSV exports, HTML). The
helpers here apply the same limits everywhere:

* ``load_yaml`` refuses oversized files and parses with ``yaml.safe_load``, which
  never constructs Python objects.
* ``csv_safe`` neutralises spreadsheet formulas, so text taken from a model's answer
  or a trace cannot run as a formula when a reviewer opens a CSV in Excel, Numbers
  or Google Sheets (CWE-1236, "CSV injection").
"""

from __future__ import annotations

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


def load_yaml(path: str | Path, max_bytes: int | None = None) -> Any:
    """Parse a YAML file safely: size-capped, ``safe_load`` only."""
    return yaml.safe_load(read_text_limited(path, max_bytes or MAX_YAML_BYTES))


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
