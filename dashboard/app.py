"""Interactive viewer for Pramana audit packs.

    pip install -e ".[dashboard]"
    streamlit run dashboard/app.py --server.address 127.0.0.1 -- --pack path/to/audit-pack

The dashboard listens on this computer only (also set in .streamlit/config.toml).

Without --pack, upload a results.json from any audit pack.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

STATE_ORDER = ["evidenced", "partial", "deficient", "not tested"]
MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")
# Streamlit's Markdown auto-links bare URLs and e-mail addresses even when escaped, so
# they are defanged with an invisible word joiner (U+2060): the text reads the same,
# but a URL in a model's answer never becomes something a reviewer can click.
WORD_JOINER = "\u2060"
LINKABLE = re.compile(r"(://|www\.|@)", re.IGNORECASE)


def defang(value: str) -> str:
    return LINKABLE.sub(lambda m: m.group(0)[0] + WORD_JOINER + m.group(0)[1:], value)


def plain(value: object) -> str:
    """Show text from a pack as text: no links, images or formatting from its contents."""
    return MARKDOWN_SPECIAL.sub(r"\\\1", defang(str(value)))


def load_results() -> tuple[dict | None, Path | None]:
    """The results and, when read from disk, the pack folder they came from."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", default=None)
    args, _ = parser.parse_known_args(sys.argv[1:])
    if args.pack:
        path = Path(args.pack) / "results.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8")), Path(args.pack)
        st.error(f"No results.json in {args.pack}")
    uploaded = st.sidebar.file_uploader("Upload results.json", type="json")
    return (json.load(uploaded) if uploaded else None), None


#: Columns of a finding's per-test table, in display order, when present.
PROBE_COLUMNS = {
    "probe_id": "Test",
    "result": "Result",
    "samples": "Samples failed",
    "technique": "Technique",
    "broken_at_turn": "Broke at turn",
    "outcome": "Outcome",
    "language": "Language",
    "response_excerpt": "Response excerpt",
}


def probe_table(probes: list[dict]) -> pd.DataFrame:
    """A finding's per-test rows as a plain table (st.dataframe renders text as text)."""
    rows = []
    for p in probes:
        failed = p.get(
            "failed", p.get("succeeded") or p.get("disclosed") or p.get("compliant") is False
        )
        if p.get("samples_evaluated", 1) == 0:
            result = "error"
        elif p.get("not_reached"):
            result = "not tested"
        else:
            result = "fail" if failed else "pass"
        row = {
            "probe_id": p.get("probe_id", ""),
            "result": result,
            "technique": p.get("technique") or p.get("rule") or "",
            "response_excerpt": p.get("response_excerpt", ""),
        }
        if "samples_failed" in p:
            row["samples"] = f"{p['samples_failed']}/{p.get('samples_evaluated', 0)}"
        for key in ("broken_at_turn", "outcome", "language"):
            if p.get(key) not in (None, ""):
                row[key] = p[key]
        rows.append(row)
    frame = pd.DataFrame(rows).fillna("")
    cols = [c for c in PROBE_COLUMNS if c in frame.columns]
    return frame[cols].rename(columns=PROBE_COLUMNS)


def show_integrity(pack: Path | None) -> None:
    """Re-verify the pack on every view, so an edited pack is never shown as genuine."""
    if pack is None:
        st.caption("Uploaded results.json: integrity not checked (open the full pack with --pack).")
        return
    from pramana.audit.ledger import verify_pack

    ok, problems = verify_pack(pack)
    if ok:
        st.success("Evidence verified: every file matches the hash chain.")
    else:
        st.error("This pack has been altered since the audit: " + plain("; ".join(problems[:5])))


def main() -> None:
    st.set_page_config(page_title="Pramana audit viewer", layout="wide")
    data, pack = load_results()
    if data is None:
        st.title("Pramana audit viewer")
        st.info(
            "Run `pramana run <spec>` and open the pack here with `--pack`, or upload results.json."
        )
        return

    system = data["system"]
    st.title(plain(f"{system['name']} v{system['version']}"))
    st.caption(plain(f"Audit {data['audit_id']} · {data['audit_date']} · owner {system['owner']}"))
    show_integrity(pack)
    run = data.get("llm_run") or {}
    if run.get("calls"):
        where = run.get("endpoint") or run.get("source") or run.get("mode", "")
        models = ", ".join(run.get("models_reported") or []) or run.get("model_requested", "")
        st.caption(
            plain(
                f"{'Live run against ' + where if run.get('mode') != 'replay' else 'Replayed from ' + where}"
                f" · {run['calls']} calls, {run.get('errors', 0)} failed"
                f" · {run.get('samples_per_probe', 1)} sample(s) per probe"
                + (f" · model {models}" if models else "")
            )
        )

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
            label = plain(f"[{row['status'].upper()}] {row['title']} · {row['check_id']}")
            with st.expander(label):
                st.markdown(plain(row["summary"]))
                if row["recommendation"] and row["status"] in ("fail", "warn", "error"):
                    st.markdown(f"**Recommendation.** {plain(row['recommendation'])}")
                if row["controls"]:
                    st.caption(plain("Controls: " + ", ".join(row["controls"])))
                details = row.get("details") if isinstance(row.get("details"), dict) else {}
                if details.get("probes"):
                    st.dataframe(probe_table(details["probes"]), hide_index=True, width="stretch")
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
