"""The bundled demos match the examples, and `pramana demo` works from an install."""

from __future__ import annotations

from pathlib import Path

import pytest

from pramana.cli import main
from pramana.demo import DEMOS

ROOT = Path(__file__).resolve().parents[1]
DEMO_SOURCES = {
    "credit-scoring": "credit_scoring",
    "support-chatbot": "support_chatbot",
    "agent-traces": "agent_traces",
}
GENERATED = {"data", "model.joblib", "__pycache__"}


def _files(base: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(base)): p.read_bytes()
        for p in sorted(base.rglob("*"))
        if p.is_file() and not GENERATED & set(p.relative_to(base).parts)
    }


@pytest.mark.parametrize("folder", sorted(DEMO_SOURCES))
def test_bundled_demos_are_identical_to_the_examples(folder):
    bundled = _files(ROOT / "src" / "pramana" / "demos" / folder)
    example = _files(ROOT / "examples" / DEMO_SOURCES[folder])
    assert bundled == example, "run `make demos` to copy examples/ into src/pramana/demos/"


def test_every_demo_is_registered():
    assert {folder for folder, _ in DEMOS.values()} == set(DEMO_SOURCES)


def test_pramana_demo_runs_and_verifies(tmp_path, capsys):
    assert main(["demo", "agent", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "gate: BLOCK" in out and "evidence pack verified: yes" in out
    assert main(["verify", str(tmp_path / "agent-traces" / "pack")]) == 0
