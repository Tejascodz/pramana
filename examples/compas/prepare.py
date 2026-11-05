"""Download ProPublica's COMPAS data and prepare it for a predictions-only audit.

COMPAS is a commercial recidivism risk score used by courts in the United States.
ProPublica obtained the scores given to defendants in Broward County, Florida, in
2013 and 2014, matched them with criminal records over the following two years,
and published the data and their analysis ("Machine Bias", 2016):
https://github.com/propublica/compas-analysis

This is a real deployed system that Pramana's authors did not build, with
published results to check the audit against. The data is not copied into this
repository: it holds names and dates of birth of real people. This script
downloads the file, checks its SHA-256, applies ProPublica's own filters, drops
every identifying column, and writes three CSV files under data/:

    data/compas_all.csv    all 6,172 defendants ProPublica analysed (evaluation)
    data/compas_2013.csv   screened in 2013 (reference period)
    data/compas_2014.csv   screened in 2014 (later period, for drift)

Columns written: sex, age, age_cat, race, juv_fel_count, juv_misd_count,
juv_other_count, priors_count, c_charge_degree, decile_score, low_risk_score and
no_recid. ``low_risk_score`` is (11 - decile) / 10, so higher means lower risk,
and ``no_recid`` is 1 for a defendant not charged with a new offence within two
years. Decile scores are ranks, not probabilities; the calibration check says so.

Usage:  python examples/compas/prepare.py
"""

from __future__ import annotations

import hashlib
import io
import sys
import urllib.request
from pathlib import Path

import pandas as pd

URL = (
    "https://raw.githubusercontent.com/propublica/compas-analysis/"
    "master/compas-scores-two-years.csv"
)
SHA256 = "c451db85908b2f7fef1d83203bedf6b71ecda0d5af468d82ae62178f91d0cc7d"
KEEP = [
    "sex", "age", "age_cat", "race", "juv_fel_count", "juv_misd_count", "juv_other_count",
    "priors_count", "c_charge_degree", "decile_score",
]  # fmt: skip
OUT = Path(__file__).resolve().parent / "data"


def download() -> bytes:
    with urllib.request.urlopen(URL, timeout=60) as response:  # noqa: S310  # nosec B310 - fixed https URL
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        sys.exit(f"Downloaded file has SHA-256 {digest}, expected {SHA256}; refusing to use it.")
    return data


def prepare(raw: bytes) -> pd.DataFrame:
    df = pd.read_csv(io.BytesIO(raw))
    # ProPublica's filters (compas-analysis, "Compas Analysis.ipynb"): a charge within 30 days
    # of the screening, a known outcome, no ordinary traffic offences, and a valid score.
    df = df[
        df["days_b_screening_arrest"].between(-30, 30)
        & (df["is_recid"] != -1)
        & (df["c_charge_degree"] != "O")
        & (df["score_text"] != "N/A")
    ]
    out = df[KEEP + ["compas_screening_date"]].copy()
    out["low_risk_score"] = (11 - out["decile_score"]) / 10
    out["no_recid"] = 1 - df["two_year_recid"].astype(int)
    return out


def main() -> None:
    data = prepare(download())
    OUT.mkdir(exist_ok=True)
    year = data.pop("compas_screening_date").str[:4]
    data.to_csv(OUT / "compas_all.csv", index=False)
    data[year == "2013"].to_csv(OUT / "compas_2013.csv", index=False)
    data[year == "2014"].to_csv(OUT / "compas_2014.csv", index=False)
    print(
        f"Wrote {len(data)} defendants to {OUT} (2013: {(year == '2013').sum()}, 2014: {(year == '2014').sum()})."
    )


if __name__ == "__main__":
    main()
