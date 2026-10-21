"""Interactive viewer for Pramana audit packs.

    pip install -e ".[dashboard]"
    streamlit run dashboard/app.py --server.address 127.0.0.1 -- --pack path/to/audit-pack

The dashboard listens on this computer only (also set in .streamlit/config.toml).

Without --pack, upload a results.json from any audit pack.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

STATE_ORDER = ["evidenced", "partial", "deficient", "not tested"]


def load_results() -> dict | None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", default=None)
    args, _ = parser.parse_known_args(sys.argv[1:])
    if args.pack:
        path = Path(args.pack) / "results.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        st.error(f"No results.json in {args.pack}")
    uploaded = st.sidebar.file_uploader("Upload results.json", type="json")
    return json.load(uploaded) if uploaded else None


def main() -> None:
    st.set_page_config(page_title="Pramana audit viewer", layout="wide")
    data = load_results()
    if data is None:
        st.title("Pramana audit viewer")
        st.info(
            "Run `pramana run <spec>` and open the pack here with `--pack`, or upload results.json."
        )
        return

    system = data["system"]
    st.title(f"{system['name']} v{system['version']}")
    st.caption(f"Audit {data['audit_id']} · {data['audit_date']} · owner {system['owner']}")

    risks = pd.DataFrame(data["risks"])
    open_risks = risks[~risks["accepted"]] if not risks.empty else risks
    cols = st.columns(4)
    cols[0].metric("Release gate", data["gate"]["decision"])
    cols[1].metric("Audit opinion", data["opinion"]["rating"])
    cols[2].metric("EU AI Act tier", data["classification"].get("eu_tier", "n/a"))
    cols[3].metric(
        "Open high/critical risks",
        int(open_risks["rating"].isin(["high", "critical"]).sum()) if not open_risks.empty else 0,
    )

    tab_risks, tab_findings, tab_coverage, tab_plan = st.tabs(
        ["Risk register", "Findings", "Framework coverage", "Remediation plan"]
    )

    with tab_risks:
        if risks.empty:
            st.success("No risks identified.")
        else:
            st.dataframe(
                risks[
                    [
                        "risk_id",
                        "title",
                        "likelihood",
                        "impact",
                        "score",
                        "rating",
                        "owner",
                        "treatment",
                    ]
                ],
                hide_index=True,
                width="stretch",
            )

    with tab_findings:
        results = pd.DataFrame(data["results"])
        statuses = st.multiselect(
            "Status", ["fail", "warn", "pass", "skipped", "error"], default=["fail", "warn"]
        )
        for _, row in results[results["status"].isin(statuses)].iterrows():
            with st.expander(f"[{row['status'].upper()}] {row['title']} · {row['check_id']}"):
                st.write(row["summary"])
                if row["recommendation"]:
                    st.markdown(f"**Recommendation.** {row['recommendation']}")
                if row["controls"]:
                    st.caption("Controls: " + ", ".join(row["controls"]))
                if row["metrics"]:
                    st.json(row["metrics"], expanded=False)

    with tab_coverage:
        rows = []
        for fw in data["coverage"]["frameworks"].values():
            for state in STATE_ORDER:
                rows.append(
                    {"framework": fw["name"], "state": state, "controls": fw["totals"][state]}
                )
        frame = pd.DataFrame(rows)
        frame = frame[frame.groupby("framework")["controls"].transform("sum") > 0]
        st.bar_chart(frame, x="framework", y="controls", color="state", horizontal=True)
        controls = pd.DataFrame(data["coverage"]["controls"])
        fw_pick = st.selectbox("Framework", sorted(controls["framework"].unique()))
        st.dataframe(
            controls[controls["framework"] == fw_pick][["id", "title", "state", "checks"]],
            hide_index=True,
            width="stretch",
        )

    with tab_plan:
        st.dataframe(pd.DataFrame(data["remediation"]), hide_index=True, width="stretch")


if __name__ == "__main__":
    main()
