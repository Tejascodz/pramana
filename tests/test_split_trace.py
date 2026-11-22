"""Splitting a large agent log into files of whole sessions, in one streaming pass."""

from __future__ import annotations

import json
import random

import pytest

from pramana.adapters.traces import split_trace
from pramana.cli import main


def _trace(path, sessions=7, events=5, seed=1):
    rng = random.Random(seed)
    lines = [
        {"session_id": f"S{s}", "event_id": f"S{s}-{e}", "type": "tool_call", "tool": "lookup",
         "timestamp": f"2026-11-01T00:00:{e:02d}Z"}
        for s in range(sessions) for e in range(events)
    ]  # fmt: skip
    rng.shuffle(lines)  # sessions interleaved, as in a real log
    lines.append({"event_id": "orphan", "type": "note"})
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    return lines


def test_no_session_is_split_across_files(tmp_path):
    lines = _trace(tmp_path / "trace.jsonl")
    result = split_trace(tmp_path / "trace.jsonl", tmp_path / "out", sessions_per_file=3)
    assert result["sessions"] == 7
    assert set(result["files"]) == {"batch_0001.jsonl", "batch_0002.jsonl", "batch_0003.jsonl",
                                    "no_session.jsonl"}  # fmt: skip
    where: dict[str, set[str]] = {}
    total = 0
    for name in result["files"]:
        for line in (tmp_path / "out" / name).read_text().splitlines():
            event = json.loads(line)
            total += 1
            where.setdefault(event.get("session_id", "-"), set()).add(name)
    assert total == len(lines)  # nothing lost or duplicated
    assert all(len(files) == 1 for sid, files in where.items() if sid != "-")
    per_file: dict[str, set[str]] = {}
    for sid, files in where.items():
        per_file.setdefault(next(iter(files)), set()).add(sid)
    assert all(len(s) <= 3 for name, s in per_file.items() if name.startswith("batch"))


def test_an_existing_split_is_not_overwritten(tmp_path):
    _trace(tmp_path / "trace.jsonl")
    split_trace(tmp_path / "trace.jsonl", tmp_path / "out", sessions_per_file=3)
    with pytest.raises(ValueError, match="already holds"):
        split_trace(tmp_path / "trace.jsonl", tmp_path / "out", sessions_per_file=3)


def test_the_command(tmp_path, capsys):
    _trace(tmp_path / "trace.jsonl")
    assert main(["split-trace", str(tmp_path / "trace.jsonl"), "--out", str(tmp_path / "o"),
                 "--sessions-per-file", "4"]) == 0  # fmt: skip
    out = capsys.readouterr().out
    assert "7 sessions written to 3 file(s)" in out and "no session split" in out
    assert main(["split-trace", str(tmp_path / "trace.jsonl"), "--out", str(tmp_path / "p"),
                 "--sessions-per-file", "0"]) == 3  # fmt: skip
