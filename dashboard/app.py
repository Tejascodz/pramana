"""Interactive viewer for Pramana audit packs.

    pip install -e ".[dashboard]"
    streamlit run dashboard/app.py --server.address 127.0.0.1 -- --pack path/to/audit-pack

The dashboard listens on this computer only (also set in .streamlit/config.toml).

Without --pack, upload a results.json from any audit pack.

Everything shown from a pack is treated as untrusted text: Markdown is escaped, HTML is
escaped, and links are defanged, so a hostile pack cannot inject formatting, scripts or
clickable links.
"""

from __future__ import annotations

import argparse
import html
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
WORD_JOINER = "⁠"
LINKABLE = re.compile(r"(://|www\.|@)", re.IGNORECASE)

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_RANK = {"fail": 0, "error": 1, "warn": 2, "pass": 3, "skipped": 4}
STATUS_LABEL = {
    "fail": "Fail",
    "error": "Not completed",
    "warn": "Warning",
    "pass": "Pass",
    "skipped": "Not run",
}
PROCESS_CHECKS = {"governance.risk_classification", "governance.manual_evidence", "audit.process"}

CSS = """
<style>
:root {
  --pv-red: #b42318; --pv-red-bg: #fef3f2; --pv-amber: #b54708; --pv-amber-bg: #fffaeb;
  --pv-green: #067647; --pv-green-bg: #ecfdf3; --pv-grey: #475467; --pv-grey-bg: #f2f4f7;
  --pv-purple: #6941c6; --pv-purple-bg: #f4f3ff; --pv-border: rgba(16, 24, 40, 0.12);
}
@media (prefers-color-scheme: dark) {
  :root {
    --pv-red: #fda29b; --pv-red-bg: rgba(240, 68, 56, 0.14); --pv-amber: #fec84b;
    --pv-amber-bg: rgba(247, 144, 9, 0.14); --pv-green: #75e0a7; --pv-green-bg: rgba(23, 178, 106, 0.14);
    --pv-grey: #cecfd2; --pv-grey-bg: rgba(152, 162, 179, 0.14); --pv-purple: #bdb4fe;
    --pv-purple-bg: rgba(122, 90, 248, 0.16); --pv-border: rgba(255, 255, 255, 0.14);
  }
}
.block-container { padding-top: 2.2rem; max-width: 1240px; }
.pv-verdict { border-radius: 14px; padding: 18px 22px; margin: 4px 0 14px; border: 1px solid var(--pv-border); }
.pv-verdict h2 { margin: 0 0 4px; font-size: 1.45rem; line-height: 1.25; }
.pv-verdict p { margin: 0; font-size: 1rem; opacity: 0.92; }
.pv-block { background: var(--pv-red-bg); } .pv-block h2 { color: var(--pv-red); }
.pv-pass { background: var(--pv-green-bg); } .pv-pass h2 { color: var(--pv-green); }
.pv-incomplete { background: var(--pv-amber-bg); } .pv-incomplete h2 { color: var(--pv-amber); }
.pv-chip { display: inline-block; font-size: 0.74rem; font-weight: 600; letter-spacing: 0.02em;
  padding: 2px 9px; border-radius: 999px; margin-right: 6px; vertical-align: 2px; }
.pv-fail, .pv-critical, .pv-high { color: var(--pv-red); background: var(--pv-red-bg); }
.pv-warn, .pv-medium { color: var(--pv-amber); background: var(--pv-amber-bg); }
.pv-ok, .pv-low { color: var(--pv-green); background: var(--pv-green-bg); }
.pv-skipped, .pv-info { color: var(--pv-grey); background: var(--pv-grey-bg); }
.pv-error { color: var(--pv-purple); background: var(--pv-purple-bg); }
.pv-card-title { font-weight: 650; font-size: 1.02rem; margin: 8px 0 2px; }
.pv-card-body { margin: 0 0 6px; opacity: 0.9; line-height: 1.5; }
.pv-muted { opacity: 0.68; font-size: 0.82rem; margin: 0; }
h1 { font-size: 2.1rem !important; line-height: 1.2 !important; }
div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stHtml"] p { margin-bottom: 0; }
div[data-testid="stMetricValue"] { font-size: 1.6rem; }
</style>
"""


def defang(value: str) -> str:
    return LINKABLE.sub(lambda m: m.group(0)[0] + WORD_JOINER + m.group(0)[1:], value)


def plain(value: object) -> str:
    """Show text from a pack as text: no links, images or formatting from its contents."""
    return MARKDOWN_SPECIAL.sub(r"\\\1", defang(str(value)))


def safe_html(value: object) -> str:
    """Pack text placed inside the viewer's own HTML: escaped, with links defanged."""
    return html.escape(defang(str(value)))


def chip(text: str, kind: str) -> str:
    return f'<span class="pv-chip pv-{kind}">{safe_html(text)}</span>'


def status_chip(status: str) -> str:
    kind = {"pass": "ok"}.get(status, status)
    return chip(STATUS_LABEL.get(status, status), kind)


def load_results() -> tuple[dict | None, Path | None]:
    """The results and, when read from disk, the pack folder they came from."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", default=None)
    args, _ = parser.parse_known_args(sys.argv[1:])
    if args.pack:
        path = Path(args.pack) / "results.json"
        if path.exists():
            return _read_json(str(path), path.stat().st_mtime_ns), Path(args.pack)
        st.error(f"No results.json in {plain(args.pack)}")
    uploaded = st.sidebar.file_uploader("Upload results.json", type="json")
    return (json.load(uploaded) if uploaded else None), None


@st.cache_data(show_spinner=False)
def _read_json(path: str, _mtime: int) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _pack_fingerprint(pack: Path) -> tuple:
    """Name, size and modification time of every file: a cache key that changes on any edit."""
    return tuple(
        sorted(
            (str(p.relative_to(pack)), p.stat().st_size, p.stat().st_mtime_ns)
            for p in pack.rglob("*")
            if p.is_file()
        )
    )


@st.cache_data(show_spinner="Checking the evidence…")
def _verify(pack: str, _fingerprint: tuple) -> tuple[bool, list[str]]:
    from pramana.audit.ledger import verify_pack

    return verify_pack(Path(pack))


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
    """Re-verify the pack whenever any of its files changes, so an edited pack is never shown as genuine."""
    if pack is None:
        st.caption("Uploaded results.json: integrity not checked (open the full pack with --pack).")
        return
    ok, problems = _verify(str(pack), _pack_fingerprint(pack))
    if ok:
        st.success("Evidence verified: every file matches the hash chain.")
    else:
        st.error("This pack has been altered since the audit: " + plain("; ".join(problems[:5])))


def verdict(data: dict) -> tuple[str, str, str]:
    """The banner: CSS class, a plain headline and one sentence saying why."""
    gate = data["gate"]
    blocking = gate.get("blocking_risks", [])
    incomplete = gate.get("incomplete_checks", [])
    not_run = gate.get("not_run", [])
    ran = gate.get("checks_run")
    if gate["decision"] == "BLOCK" and blocking:
        why = (
            f"{len(blocking)} risk{'s' if len(blocking) != 1 else ''} rated "
            f"{' or '.join(gate.get('block_on', ['critical', 'high']))} must be treated first."
        )
        if incomplete:
            why += f" {len(incomplete)} test(s) also could not be completed."
        return "pv-block", "Release blocked", why
    if gate["decision"] == "BLOCK":
        return (
            "pv-incomplete",
            "Release blocked: the audit is incomplete",
            f"{len(incomplete)} test(s) could not be completed, so the audit cannot vouch for this "
            "system yet. Fix the inputs and run it again.",
        )
    why = "No blocking risk was found"
    why += f" in the {ran} checks that ran." if ran else "."
    if not_run:
        why += f" {len(not_run)} check(s) did not run and are not covered by this decision."
    return "pv-pass", "Release can proceed", why


def show_header(data: dict, pack: Path | None) -> None:
    system = data["system"]
    st.title(plain(f"{system['name']} v{system['version']}"))
    st.caption(plain(f"Audit {data['audit_id']} · {data['audit_date']} · owner {system['owner']}"))
    kind, headline, why = verdict(data)
    st.html(
        f'<div class="pv-verdict {kind}"><h2>{safe_html(headline)}</h2><p>{safe_html(why)}</p></div>'
    )
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


def show_metrics(data: dict) -> None:
    results = data["results"]
    ran = [r for r in results if r["status"] != "skipped"]
    passed = sum(1 for r in ran if r["status"] == "pass")
    open_risks = [r for r in data["risks"] if not r["accepted"]]
    serious = sum(1 for r in open_risks if r["rating"] in ("critical", "high"))
    cols = st.columns(5)
    cols[0].metric("EU AI Act tier", data["classification"].get("eu_tier", "n/a"))
    cols[1].metric("Audit opinion", data["opinion"]["rating"])
    cols[2].metric("Checks passed", f"{passed} of {len(ran)}")
    cols[3].metric("Open high/critical risks", serious)
    cols[4].metric("Checks not run", len(results) - len(ran))


def ordered(results: list[dict]) -> list[dict]:
    return sorted(
        results,
        key=lambda r: (
            STATUS_RANK.get(r["status"], 9),
            SEVERITY_RANK.get(r.get("severity", "info"), 9),
            r["check_id"],
        ),
    )


def card(result: dict, body: str) -> None:
    with st.container(border=True):
        chips = status_chip(result["status"])
        if result["status"] in ("fail", "warn", "error"):
            chips += chip(result.get("severity", ""), result.get("severity", "info"))
        st.html(
            f"<div>{chips}</div>"
            f'<p class="pv-card-title">{safe_html(result["title"])}</p>'
            f'<p class="pv-card-body">{safe_html(body)}</p>'
            f'<p class="pv-muted">{safe_html(result["category"])} · {safe_html(result["check_id"])}</p>'
        )


def show_overview(data: dict) -> None:
    results = ordered(data["results"])
    problems = [r for r in results if r["status"] in ("fail", "error", "warn")]
    working = [r for r in results if r["status"] == "pass" and r["check_id"] not in PROCESS_CHECKS]
    skipped = [r for r in results if r["status"] == "skipped"]

    left, right = st.columns([3, 2], gap="large")
    with left:
        st.subheader("What needs attention")
        if not problems:
            st.success("Nothing to fix among the checks that ran.")
        for r in problems:
            card(r, r.get("plain_summary") or r["summary"])
        st.caption("Open the Findings tab for the evidence behind each item.")
    with right:
        st.subheader("What is working")
        if not working:
            st.info("No technical test passed in this audit.")
        for r in working:
            card(r, r.get("plain_summary") or r["summary"])
        st.subheader("Not tested in this audit")
        if not skipped:
            st.caption("Every applicable check ran.")
        else:
            st.caption(
                "The release decision does not cover these. List any your policy depends on "
                "under gate.required_checks to make them mandatory."
            )
            for r in skipped:
                card(r, r["summary"].removeprefix("Skipped: "))


def show_findings(data: dict) -> None:
    results = pd.DataFrame(ordered(data["results"]))
    top = st.columns([3, 2, 3])
    statuses = top[0].multiselect(
        "Show",
        ["fail", "warn", "error", "pass", "skipped"],
        default=["fail", "warn", "error"],
        format_func=lambda s: STATUS_LABEL.get(s, s),
    )
    areas = ["All areas"] + sorted(results["category"].unique())
    area = top[1].selectbox("Area", areas)
    query = top[2].text_input("Search", placeholder="check, word in a summary…").strip().lower()

    shown = results[results["status"].isin(statuses)]
    if area != "All areas":
        shown = shown[shown["category"] == area]
    if query:
        text = (shown["check_id"] + " " + shown["title"] + " " + shown["summary"]).str.lower()
        shown = shown[text.str.contains(query, regex=False)]
    st.caption(f"{len(shown)} of {len(results)} checks shown, most serious first.")

    for _, row in shown.iterrows():
        label = plain(
            f"{STATUS_LABEL.get(row['status'], row['status'])} · {row['severity']} · "
            f"{row['title']} · {row['check_id']}"
        )
        with st.expander(label, expanded=False):
            if row.get("plain_summary"):
                st.markdown(f"**In plain words.** {plain(row['plain_summary'])}")
            st.markdown(plain(row["summary"]))
            if row["recommendation"] and row["status"] in ("fail", "warn", "error"):
                st.markdown(f"**Recommendation.** {plain(row['recommendation'])}")
            if row["controls"]:
                st.caption(plain("Controls: " + ", ".join(row["controls"])))
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if details.get("probes"):
                st.dataframe(probe_table(details["probes"]), hide_index=True, width="stretch")
            if row["metrics"]:
                st.caption("Measured values (click to expand)")
                st.json(row["metrics"], expanded=False)


def show_risks(data: dict) -> None:
    risks = pd.DataFrame(data["risks"])
    if risks.empty:
        st.success("No risks identified.")
        return
    st.caption(
        "Score = likelihood × impact (1 to 25). Accepted risks stay listed but do not block the release."
    )
    st.dataframe(
        risks[
            ["risk_id", "title", "rating", "score", "likelihood", "impact", "owner", "treatment"]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            "risk_id": st.column_config.TextColumn("Risk", width="small"),
            "title": st.column_config.TextColumn("Title", width="medium"),
            "rating": st.column_config.TextColumn("Rating", width="small"),
            "score": st.column_config.ProgressColumn(
                "Score", min_value=0, max_value=25, format="%d"
            ),
            "likelihood": st.column_config.NumberColumn("Likelihood", width="small"),
            "impact": st.column_config.NumberColumn("Impact", width="small"),
            "owner": st.column_config.TextColumn("Owner"),
            "treatment": st.column_config.TextColumn("Treatment"),
        },
    )


def show_coverage(data: dict) -> None:
    st.caption(
        "Evidenced: a test produced passing evidence. Partial or deficient: a test found gaps. "
        "Not tested: the control needs organisational evidence, such as a policy or sign-off."
    )
    rows = []
    for fw in data["coverage"]["frameworks"].values():
        for state in STATE_ORDER:
            rows.append({"framework": fw["name"], "state": state, "controls": fw["totals"][state]})
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


def main() -> None:
    st.set_page_config(
        page_title="Pramana audit viewer", layout="wide", initial_sidebar_state="collapsed"
    )
    st.html(CSS)
    data, pack = load_results()
    if data is None:
        st.title("Pramana audit viewer")
        st.info(
            "Run `pramana run <spec>` and open the pack here with `--pack`, or upload "
            "results.json from the sidebar."
        )
        return

    show_header(data, pack)
    show_metrics(data)
    tab_overview, tab_findings, tab_risks, tab_coverage, tab_plan = st.tabs(
        ["Overview", "Findings", "Risk register", "Framework coverage", "Remediation plan"]
    )
    with tab_overview:
        show_overview(data)
    with tab_findings:
        show_findings(data)
    with tab_risks:
        show_risks(data)
    with tab_coverage:
        show_coverage(data)
    with tab_plan:
        st.dataframe(pd.DataFrame(data["remediation"]), hide_index=True, width="stretch")

    from pramana import NOTICE

    st.divider()
    st.caption(plain(NOTICE))


if __name__ == "__main__":
    main()
