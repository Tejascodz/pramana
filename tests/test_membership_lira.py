"""The likelihood-ratio membership-inference attack (offline LiRA, Carlini et al., 2022).

A model that memorises its training rows must be caught far more often at a low
false-positive rate than by the loss-threshold attack; a model that does not memorise must
stay near chance. Both directions are tested on synthetic data with a known answer.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from pramana.checks.privacy import lira_offline
from pramana.metrics import safe_auc


def _data(n=800, seed=0):
    rng = np.random.default_rng(seed)
    X = pd.DataFrame(rng.normal(size=(2 * n, 6)), columns=[f"f{i}" for i in range(6)])
    noise = rng.random(2 * n) < 0.3  # labels a model can only fit by memorising
    y = ((X["f0"] + X["f1"] > 0) ^ noise).astype(int).to_numpy()
    return X, y, n


def test_lira_finds_a_memorising_model_far_more_often_at_a_low_false_positive_rate():
    """Measured: a random forest that memorises its rows; at 1% false positives LiRA finds
    0.42 of training rows, the loss-threshold attack 0.12."""
    from pramana.checks.privacy import _per_sample_loss, _tpr_at_fpr

    X, y, n = _data()
    model = RandomForestClassifier(n_estimators=40, random_state=0).fit(X[:n], y[:n])
    scores = lira_offline(model, X, y, shadows=8, seed=1)
    labels = np.r_[np.ones(n), np.zeros(n)]
    assert safe_auc(labels, scores) > 0.9
    loss = _per_sample_loss(y, model.predict_proba(X)[:, 1])
    lira_tpr = _tpr_at_fpr(-scores[:n], -scores[n:], 0.01)
    assert lira_tpr > 2 * _tpr_at_fpr(loss[:n], loss[n:], 0.01)


def test_lira_stays_near_chance_for_a_model_that_does_not_memorise():
    X, y, n = _data()
    model = LogisticRegression().fit(X[:n], y[:n])
    scores = lira_offline(model, X, y, shadows=8, seed=1)
    labels = np.r_[np.ones(n), np.zeros(n)]
    assert abs(safe_auc(labels, scores) - 0.5) < 0.06


def test_lira_is_reproducible():
    X, y, n = _data(300)
    model = DecisionTreeClassifier(random_state=0).fit(X[:n], y[:n])
    assert np.array_equal(lira_offline(model, X, y, 4, 7), lira_offline(model, X, y, 4, 7))


def test_a_model_that_cannot_be_retrained_is_reported_not_attacked():
    class Frozen:
        classes_ = np.array([0, 1])

        def predict_proba(self, X):
            return np.tile([0.4, 0.6], (len(X), 1))

    X, y, _ = _data(100)
    assert lira_offline(Frozen(), X, y, 4, 1) is None


def _audit(tmp_path, model, shadows=None):
    import joblib

    from pramana.audit.engine import run_audit
    from pramana.spec import load_spec

    X, y, n = _data()
    train = X[:n].assign(approved=y[:n])
    test = X[n:].assign(approved=y[n:])
    train.to_csv(tmp_path / "train.csv", index=False)
    test.to_csv(tmp_path / "test.csv", index=False)
    joblib.dump(model.fit(X[:n], y[:n]), tmp_path / "model.joblib")
    spec = {
        "system": {"name": "m", "version": "1", "type": "tabular_classifier", "owner": "o"},
        "use_case": {"domain": "other"},
        "trust_pickled_model": True,
        "artifacts": {"model": "model.joblib", "reference_data": "train.csv",
                      "evaluation_data": "test.csv"},
        "target": "approved", "positive_label": 1,
        "checks": {"include": ["privacy.membership_inference"]},
    }  # fmt: skip
    if shadows is not None:
        spec["checks"]["options"] = {"privacy.membership_inference": {"shadow_models": shadows}}
    (tmp_path / "audit.yaml").write_text(yaml.safe_dump(spec))
    return run_audit(load_spec(tmp_path / "audit.yaml"), tmp_path / "pack").result(
        "privacy.membership_inference"
    )


def test_the_check_reports_the_stronger_attack(tmp_path):
    check = _audit(tmp_path, RandomForestClassifier(n_estimators=40, random_state=0))
    m = check.metrics
    assert m["lira_shadow_models"] == 8 and m["lira_auc"] > 0.9
    assert m["lira_tpr_at_1pct_fpr"] > m["tpr_at_1pct_fpr"]  # stronger where it matters
    assert check.status.value == "fail" and "stronger of the two attacks" in check.summary


def test_shadow_models_can_be_turned_off(tmp_path):
    check = _audit(tmp_path, LogisticRegression(), shadows=0)
    assert "lira_auc" not in check.metrics and "did not run" in check.summary


@pytest.mark.parametrize("value", [True, -1, 65, 2.5, "8"])
def test_a_bad_shadow_model_count_is_refused(tmp_path, value):
    from pramana.spec import SpecError

    with pytest.raises(SpecError, match="whole number from 0 to 64"):
        _audit(tmp_path, LogisticRegression(), shadows=value)
