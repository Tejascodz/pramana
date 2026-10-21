"""Build the synthetic credit-scoring case study.

Generates applicant data for a fictional Indian lender, trains a gradient-boosted
model and writes everything Pramana needs to audit it. The data is fully
synthetic. Several defects are planted on purpose so the audit can be checked
against a known ground truth:

* historical labels under-record repayment by rural women (label bias)
* a pincode-derived risk band that closely tracks residence (proxy feature)
* bureau scores missing for many new-to-credit applicants (data quality)
* applicant e-mail and mobile columns left in the extracts (personal data)
* a production sample where incomes and the gig-worker share have shifted (drift)

Run from the repository root:  python examples/credit_scoring/build_model.py
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
SEED = 2026

FEATURES = [
    "monthly_income",
    "employment_type",
    "pincode_risk_band",
    "credit_history_months",
    "existing_emis",
    "debt_to_income",
    "loan_amount",
    "bureau_score",
    "years_at_address",
]
CATEGORICAL = ["employment_type", "pincode_risk_band"]


def generate(n: int, rng: np.random.Generator, *, drifted: bool = False) -> pd.DataFrame:
    gender = rng.choice(["female", "male"], size=n, p=[0.45, 0.55])
    age_band = rng.choice(["18-25", "26-40", "41-60", "60+"], size=n, p=[0.18, 0.45, 0.30, 0.07])
    residence = rng.choice(["urban", "semi_urban", "rural"], size=n, p=[0.45, 0.30, 0.25])

    employment = np.empty(n, dtype=object)
    for i in range(n):
        if residence[i] == "rural" and gender[i] == "female":
            p = [0.10, 0.55, 0.10, 0.25]
        elif residence[i] == "rural":
            p = [0.30, 0.10, 0.15, 0.45]
        elif gender[i] == "female":
            p = [0.42, 0.18, 0.32, 0.08]
        else:
            p = [0.55, 0.25, 0.12, 0.08]
        if drifted:
            p = [p[0] * 0.6, p[1], p[2] * 2.6, p[3]]
            p = list(np.array(p) / sum(p))
        employment[i] = rng.choice(["salaried", "self_employed", "gig", "agriculture"], p=p)

    base_income = {"urban": 11.0, "semi_urban": 10.6, "rural": 10.2}
    income = np.exp(np.array([base_income[r] for r in residence]) + rng.normal(0, 0.45, n))
    income *= np.where(employment == "salaried", 1.15, 1.0)
    if drifted:
        income *= 1.35
    income = np.round(income, -2)

    band_by_residence = {
        "urban": ["A", "B", "B", "C"],
        "semi_urban": ["B", "C", "C", "D"],
        "rural": ["D", "E", "E", "E"],
    }
    pincode_band = np.array([rng.choice(band_by_residence[r]) for r in residence])

    history = np.clip(
        rng.gamma(2.2, 26, n) * np.where(age_band == "18-25", 0.4, 1.0), 0, 240
    ).round()
    emis = rng.poisson(1.1, n)
    loan = np.round(income * rng.uniform(3, 18, n), -3)
    dti = np.clip(
        emis * rng.uniform(0.04, 0.12, n) + loan / (income * 60) + rng.normal(0, 0.04, n), 0, 0.95
    )
    bureau = np.clip(rng.normal(690, 70, n) + history * 0.35 - dti * 120, 300, 900).round()
    years_at_address = np.clip(rng.exponential(5, n), 0, 40).round(1)

    logit = (
        0.012 * (bureau - 700)
        + 0.9 * (np.log(income) - 10.6)
        - 3.2 * (dti - 0.3)
        + 0.004 * history
        + 0.03 * years_at_address
        + 1.3
    )
    repaid = (rng.random(n) < 1 / (1 + np.exp(-logit))).astype(int)

    # Historical label bias: collections practice recorded many rural women as defaulters.
    biased = (gender == "female") & (residence == "rural") & (repaid == 1)
    repaid[biased & (rng.random(n) < 0.45)] = 0

    new_to_credit = history < 12
    missing_rate = 0.75 if not drifted else 0.9
    bureau = bureau.astype(float)
    bureau[new_to_credit & (rng.random(n) < missing_rate)] = np.nan

    ids = rng.integers(10_000, 99_999, n)
    return pd.DataFrame(
        {
            "applicant_id": [
                f"APP-{i:06d}" for i in rng.permutation(n) + (500_000 if drifted else 0)
            ],
            "gender": gender,
            "age_band": age_band,
            "residence": residence,
            "monthly_income": income,
            "employment_type": employment,
            "pincode_risk_band": pincode_band,
            "credit_history_months": history,
            "existing_emis": emis,
            "debt_to_income": dti.round(3),
            "loan_amount": loan,
            "bureau_score": bureau,
            "years_at_address": years_at_address,
            "contact_email": [f"applicant{i}@example.in" for i in ids],
            "mobile": [f"9{rng.integers(100_000_000, 999_999_999)}" for _ in range(n)],
            "repaid": repaid,
        }
    )


def train(df: pd.DataFrame) -> Pipeline:
    pre = ColumnTransformer(
        [
            (
                "cat",
                OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
                CATEGORICAL,
            )
        ],
        remainder="passthrough",
        verbose_feature_names_out=False,
    )
    model = HistGradientBoostingClassifier(
        max_iter=220,
        learning_rate=0.06,
        max_leaf_nodes=31,
        min_samples_leaf=25,
        early_stopping=False,
        random_state=SEED,
    )
    pipeline = Pipeline([("prep", pre), ("clf", model)])
    pipeline.fit(df[FEATURES], df["repaid"])
    return pipeline


def main() -> None:
    rng = np.random.default_rng(SEED)
    DATA.mkdir(exist_ok=True)
    history = generate(12_000, rng)
    train_df = history.sample(frac=0.7, random_state=SEED)
    test_df = history.drop(train_df.index)
    production = generate(3_000, rng, drifted=True).drop(columns=["repaid"])

    duplicates = test_df.sample(60, random_state=SEED)
    test_df = pd.concat([test_df, duplicates]).sample(frac=1.0, random_state=SEED)

    model = train(train_df)
    train_df.to_csv(DATA / "train.csv", index=False)
    test_df.to_csv(DATA / "test.csv", index=False)
    production.to_csv(DATA / "production_sample.csv", index=False)
    joblib.dump(model, HERE / "model.joblib")
    print(f"train={len(train_df)} test={len(test_df)} production={len(production)}")
    print("wrote data/*.csv and model.joblib")


if __name__ == "__main__":
    main()
