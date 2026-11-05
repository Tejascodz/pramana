"""The interactive viewer renders real packs, every tab, with per-test detail."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
testing = pytest.importorskip("streamlit.testing.v1")


def _app(pack: Path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["app.py", "--pack", str(pack)])
    at = testing.AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception, [e.message for e in at.exception]
    return at


@pytest.mark.parametrize(
    "pack",
    ["llama32_3b_guarded_v074", "llama32_3b_agent_sandbox", "agent_traces", "support_chatbot"],
)
def test_the_viewer_opens_published_packs(pack, monkeypatch):
    at = _app(ROOT / "docs" / "sample-audits" / pack, monkeypatch)
    assert at.title[0].value
    assert any("Evidence verified" in s.value for s in at.success)
    assert len(at.tabs) == 4


def test_findings_show_the_per_test_table_for_a_real_run(monkeypatch):
    at = _app(ROOT / "docs" / "sample-audits" / "llama32_3b_guarded_v074", monkeypatch)
    at.multiselect[0].set_value(["fail", "warn", "pass"]).run()
    assert not at.exception
    tables = [df.value for df in at.dataframe]
    probe_tables = [t for t in tables if "Response excerpt" in t.columns]
    assert probe_tables, "no per-test table in the findings"
    tests = set().union(*(set(t["Test"]) for t in probe_tables))
    assert "LIVE-PI-H1" in tests and "LIVE-MT-H6" in tests  # injection and held-out conversation
    assert any("Samples failed" in t.columns for t in probe_tables)
    assert any("Live run" in c.value or "Replayed" in c.value for c in at.caption)


def test_recommendations_are_only_shown_for_problems(monkeypatch):
    at = _app(ROOT / "docs" / "sample-audits" / "llama32_3b_guarded_v074", monkeypatch)
    at.multiselect[0].set_value(["pass"]).run()
    assert not any("Recommendation" in m.value for m in at.markdown)


def test_an_altered_pack_is_flagged(tmp_path, monkeypatch):
    import shutil

    pack = tmp_path / "pack"
    shutil.copytree(ROOT / "docs" / "sample-audits" / "agent_traces", pack)
    (pack / "evidence" / "4-testing" / "agent.honeypot.json").write_text("{}")  # an added file
    at = _app(pack, monkeypatch)
    assert any("altered" in e.value for e in at.error)
