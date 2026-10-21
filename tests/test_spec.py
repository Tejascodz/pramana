import pytest

from pramana.cli import main
from pramana.spec import SpecError, load_spec


def _write(tmp_path, text):
    path = tmp_path / "audit.yaml"
    path.write_text(text)
    return path


def test_missing_sections_are_reported(tmp_path):
    with pytest.raises(SpecError, match="use_case"):
        load_spec(_write(tmp_path, "system: {name: x, version: '1', type: agent, owner: o}\n"))


def test_unknown_system_type(tmp_path):
    with pytest.raises(SpecError, match="system.type"):
        load_spec(
            _write(
                tmp_path, "system: {name: x, version: '1', type: robot, owner: o}\nuse_case: {}\n"
            )
        )


def test_tabular_needs_model_or_scores(tmp_path):
    text = (
        "system: {name: x, version: '1', type: tabular_classifier, owner: o}\n"
        "use_case: {}\nartifacts: {evaluation_data: d.csv}\ntarget: y\n"
    )
    with pytest.raises(SpecError, match="score_column"):
        load_spec(_write(tmp_path, text))
    assert load_spec(_write(tmp_path, text + "score_column: p\n")).score_column == "p"


def test_paths_resolve_relative_to_the_spec(tmp_path):
    text = (
        "system: {name: x, version: '1', type: tabular_classifier, owner: o}\n"
        "use_case: {}\nartifacts: {model: m.joblib, evaluation_data: data/e.csv}\ntarget: y\n"
    )
    spec = load_spec(_write(tmp_path, text))
    assert spec.artifact("evaluation_data") == tmp_path / "data" / "e.csv"


def test_init_writes_a_loadable_template(tmp_path):
    target = tmp_path / "new.yaml"
    assert main(["init", str(target)]) == 0
    spec = load_spec(target)
    assert spec.system_type == "tabular_classifier"
    assert main(["init", str(target)]) == 3
