"""Regression tests: a spec that could weaken an audit result is refused when loaded.

A threshold of NaN made every comparison false, so fairness, drift, data-quality and
prompt-injection checks passed whatever they measured; a repeated YAML key silently
replaced a strict gate with a lenient one; a misspelt check id silently dropped a check.
Each of these is now a SpecError before any check runs. Every test here failed before
0.8.0 (except the ones marked as controls).
"""

from __future__ import annotations

import math

import pytest
import yaml

from pramana.spec import DEFAULT_THRESHOLDS, SpecError, load_spec

BASE = {
    "system": {"name": "S", "version": "1", "type": "llm_application", "owner": "o"},
    "use_case": {"domain": "other"},
}


def write_spec(tmp_path, extra: dict | None = None, text: str | None = None):
    path = tmp_path / "audit.yaml"
    path.write_text(text if text is not None else yaml.safe_dump({**BASE, **(extra or {})}))
    return path


def test_control_a_plain_spec_loads(tmp_path):
    spec = load_spec(write_spec(tmp_path, {"thresholds": {"min_auc": 0.75}}))
    assert spec.threshold("min_auc") == 0.75


# ---------------------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------------------

FALSE_PASS_THRESHOLDS = [
    "disparate_impact_min",  # fairness
    "equalized_odds_max",  # fairness
    "psi_warn",  # drift
    "psi_fail",  # drift
    "missing_rate_max",  # data quality
    "duplicate_rate_max",  # data quality
    "llm_attack_success_max",  # prompt injection
    "llm_groundedness_min",  # LLM evaluation
]


@pytest.mark.parametrize("key", FALSE_PASS_THRESHOLDS)
@pytest.mark.parametrize("value", [".nan", ".inf", "-.inf"])
def test_non_finite_thresholds_are_refused(tmp_path, key, value):
    text = yaml.safe_dump(BASE) + f"thresholds:\n  {key}: {value}\n"
    with pytest.raises(SpecError, match="finite"):
        load_spec(write_spec(tmp_path, text=text))


@pytest.mark.parametrize(
    "key,value",
    [
        ("disparate_impact_min", -0.1),
        ("disparate_impact_min", 1.5),
        ("llm_attack_success_max", 2),
        ("missing_rate_max", -1),
        ("psi_fail", -0.25),
        ("llm_latency_p95_max_ms", -5),
        ("min_group_size", 0),
        ("min_group_size", -3),
        ("llm_min_samples", 0),
    ],
)
def test_out_of_range_thresholds_are_refused(tmp_path, key, value):
    with pytest.raises(SpecError, match="at least|at most"):
        load_spec(write_spec(tmp_path, {"thresholds": {key: value}}))


@pytest.mark.parametrize("value", [True, False, "0.8", "high", None, [0.8], {"x": 1}])
def test_thresholds_that_are_not_numbers_are_refused(tmp_path, value):
    with pytest.raises(SpecError, match="number"):
        load_spec(write_spec(tmp_path, {"thresholds": {"disparate_impact_min": value}}))


@pytest.mark.parametrize("key", ["min_group_size", "llm_min_samples", "llm_max_output_chars"])
def test_counts_must_be_whole_numbers(tmp_path, key):
    with pytest.raises(SpecError, match="whole number"):
        load_spec(write_spec(tmp_path, {"thresholds": {key: 2.5}}))
    assert load_spec(write_spec(tmp_path, {"thresholds": {key: 30}})).threshold(key) == 30


def test_a_misspelt_threshold_is_refused_with_a_suggestion(tmp_path):
    with pytest.raises(SpecError, match="Did you mean 'disparate_impact_min'"):
        load_spec(write_spec(tmp_path, {"thresholds": {"disparate_impact_mn": 0.8}}))


def test_psi_warn_above_psi_fail_is_refused(tmp_path):
    with pytest.raises(SpecError, match="psi_warn"):
        load_spec(write_spec(tmp_path, {"thresholds": {"psi_warn": 0.5, "psi_fail": 0.2}}))


def test_a_threshold_set_in_code_is_still_checked(tmp_path):
    spec = load_spec(write_spec(tmp_path))
    spec.thresholds["disparate_impact_min"] = math.nan
    with pytest.raises(SpecError):
        spec.threshold("disparate_impact_min")


def test_every_default_threshold_is_valid(tmp_path):
    spec = load_spec(write_spec(tmp_path))
    for key in DEFAULT_THRESHOLDS:
        spec.threshold(key)


# ---------------------------------------------------------------------------------------
# Duplicate YAML keys
# ---------------------------------------------------------------------------------------


def test_a_repeated_gate_section_is_refused(tmp_path):
    text = (
        yaml.safe_dump(BASE)
        + "gate:\n  block_on: [critical, high, medium]\n"
        + "gate:\n  block_on: [critical]\n"
    )
    with pytest.raises(SpecError, match="repeats a key"):
        load_spec(write_spec(tmp_path, text=text))


def test_a_repeated_nested_key_is_refused(tmp_path):
    text = yaml.safe_dump(BASE) + "thresholds:\n  min_auc: 0.9\n  min_auc: 0.1\n"
    with pytest.raises(SpecError, match="repeats a key"):
        load_spec(write_spec(tmp_path, text=text))


def test_control_yaml_merge_keys_still_work(tmp_path):
    from pramana.safeio import parse_yaml

    data = parse_yaml("base: &b {x: 1, y: 2}\nother:\n  <<: *b\n  y: 3\n")
    assert data["other"] == {"x": 1, "y": 3}


# ---------------------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------------------


def test_an_empty_block_on_is_refused(tmp_path):
    with pytest.raises(SpecError, match="block_on is empty"):
        load_spec(write_spec(tmp_path, {"gate": {"block_on": []}}))


@pytest.mark.parametrize("gate", [[], "strict", 1, True])
def test_a_gate_that_is_not_a_mapping_is_refused(tmp_path, gate):
    with pytest.raises(SpecError, match="gate"):
        load_spec(write_spec(tmp_path, {"gate": gate}))


def test_a_misspelt_gate_setting_is_refused(tmp_path):
    with pytest.raises(SpecError, match="Did you mean 'block_on'"):
        load_spec(write_spec(tmp_path, {"gate": {"blockon": ["critical"]}}))


def test_control_an_empty_gate_section_uses_the_defaults(tmp_path):
    text = yaml.safe_dump(BASE) + "gate:\n"
    assert load_spec(write_spec(tmp_path, text=text)).gate == {}


# ---------------------------------------------------------------------------------------
# Check selection
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("section", ["include", "exclude"])
def test_an_unknown_check_id_is_refused(tmp_path, section):
    ids = ["llm.prompt_injection", "llm.prompt_injecton"]
    with pytest.raises(SpecError, match="Did you mean 'llm.prompt_injection'"):
        load_spec(write_spec(tmp_path, {"checks": {section: ids}}))


@pytest.mark.parametrize("section", ["include", "exclude"])
@pytest.mark.parametrize("value", ["llm.prompt_injection", 3, {"a": 1}, [1, 2]])
def test_include_and_exclude_must_be_lists_of_ids(tmp_path, section, value):
    with pytest.raises(SpecError, match="list of check ids"):
        load_spec(write_spec(tmp_path, {"checks": {section: value}}))


def test_an_empty_include_is_refused(tmp_path):
    with pytest.raises(SpecError, match="no check would run"):
        load_spec(write_spec(tmp_path, {"checks": {"include": []}}))


@pytest.mark.parametrize(
    "options,match",
    [
        ({"nope.check": {}}, "not a Pramana check"),
        ({"robustness.perturbation": "x"}, "mapping"),
        ({"robustness.perturbation": {"monotone_up": ["a"]}}, "not an option"),
        ({"robustness.perturbation": {"monotone_increasing": "income"}}, "list of column"),
        ({"fairness.proxy_features": {"allow_sensitive_inputs": "no"}}, "true or false"),
        ({"llm.prompt_injection": {"anything": 1}}, "no options"),
        ([1, 2], "map check ids"),
    ],
)
def test_malformed_check_options_are_refused(tmp_path, options, match):
    with pytest.raises(SpecError, match=match):
        load_spec(write_spec(tmp_path, {"checks": {"options": options}}))


def test_a_misspelt_checks_setting_is_refused(tmp_path):
    with pytest.raises(SpecError, match="include, exclude or options"):
        load_spec(write_spec(tmp_path, {"checks": {"exlude": ["llm.prompt_injection"]}}))


def test_control_valid_check_selection_works(tmp_path):
    spec = load_spec(
        write_spec(
            tmp_path,
            {"checks": {"include": ["llm.prompt_injection"], "exclude": ["llm.groundedness"]}},
        )
    )
    assert spec.check_enabled("llm.prompt_injection")
    assert not spec.check_enabled("llm.groundedness")
    assert not spec.check_enabled("llm.policy_compliance")


# ---------------------------------------------------------------------------------------
# Other numeric fields
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, "0.5", None])
def test_decision_threshold_must_be_a_number(tmp_path, value):
    with pytest.raises(SpecError, match="decision_threshold"):
        load_spec(write_spec(tmp_path, {"decision_threshold": value}))


def test_decision_threshold_must_be_finite(tmp_path):
    text = yaml.safe_dump(BASE) + "decision_threshold: .nan\n"
    with pytest.raises(SpecError, match="decision_threshold"):
        load_spec(write_spec(tmp_path, text=text))


@pytest.mark.parametrize("value", [True, 1.5, -1, "7"])
def test_seed_must_be_a_whole_number(tmp_path, value):
    with pytest.raises(SpecError, match="seed"):
        load_spec(write_spec(tmp_path, {"seed": value}))
