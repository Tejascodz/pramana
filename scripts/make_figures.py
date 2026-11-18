"""Draw the README result charts from the committed audit packs.

Every number comes from a results.json under docs/sample-audits; the only constants are
ProPublica's published COMPAS error rates, cited below. The charts are plain SVG, so the
script needs nothing beyond the standard library.

    python scripts/make_figures.py
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "docs" / "sample-audits"
OUT = ROOT / "docs" / "img"

# ProPublica, "How We Analyzed the COMPAS Recidivism Algorithm" (2016), error-rate table.
PROPUBLICA = {
    ("African-American", "higher_risk_no_reoffence"): 0.449,
    ("Caucasian", "higher_risk_no_reoffence"): 0.235,
    ("African-American", "lower_risk_reoffended"): 0.280,
    ("Caucasian", "lower_risk_reoffended"): 0.477,
}

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
INK, MUTED, GRID = "#1f2937", "#6b7280", "#e5e7eb"
BLUE, GREY = "#2f6fdb", "#9aa4b2"


def check(pack: str, check_id: str) -> dict:
    results = json.loads((PACKS / pack / "results.json").read_text(encoding="utf-8"))
    return next(r for r in results["results"] if r["check_id"] == check_id)


def rate_row(pack: str, check_id: str, label: str, colour: str) -> dict:
    c = check(pack, check_id)
    probes = c["details"]["probes"]
    failed = sum(p["samples_failed"] for p in probes)
    judged = sum(p["samples_evaluated"] for p in probes)
    m = c["metrics"]
    return {
        "label": label,
        "value": failed / judged,
        "low": m["ci_low"],
        "high": m["ci_high"],
        "note": f"{failed} of {judged} samples",
        "colour": colour,
    }


def text(x, y, s, size=13, colour=INK, anchor="start", weight=400) -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{colour}" '
        f'text-anchor="{anchor}" font-weight="{weight}">{escape(s)}</text>'
    )


def svg(width: int, height: int, body: list[str], title: str, desc: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{FONT}" role="img">\n'
        f"<title>{escape(title)}</title>\n<desc>{escape(desc)}</desc>\n"
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>\n'
        + "\n".join(body)
        + "\n</svg>\n"
    )


def attack_chart() -> str:
    rows = [
        rate_row("llama32_3b_x3_baseline", "llm.prompt_injection",
                 "Single-message injection, baseline build", GREY),
        rate_row("llama32_3b_x3_guarded", "llm.prompt_injection",
                 "Single-message injection, guarded build", BLUE),
        rate_row("llama32_3b_guarded_rescored", "llm.obfuscation",
                 "Disguised injection, guarded build", BLUE),
        rate_row("llama32_3b_guarded_rescored", "llm.multi_turn",
                 "Multi-turn conversations, guarded build", BLUE),
    ]  # fmt: skip
    left, plot, top, row_h = 300, 400, 70, 46
    value_x = left + plot + 24
    width = value_x + 250
    scale_max = 0.35
    height = top + row_h * len(rows) + 56

    def x(v: float) -> float:
        return left + plot * v / scale_max

    body = [
        text(24, 30, "Attack success on llama3.2:3b behind the reference assistant", 16, weight=650),
        text(24, 50, "Share of judged samples in which the attack worked; whiskers are 95% Wilson "
             "intervals. Three samples per probe.", 12, MUTED),
    ]  # fmt: skip
    for tick in (0, 0.1, 0.2, 0.3):
        body.append(f'<line x1="{x(tick):.1f}" y1="{top - 6}" x2="{x(tick):.1f}" '
                    f'y2="{top + row_h * len(rows) - 10}" stroke="{GRID}" stroke-width="1"/>')  # fmt: skip
        body.append(text(x(tick), top + row_h * len(rows) + 8, f"{tick:.0%}", 12, MUTED, "middle"))
    for i, r in enumerate(rows):
        cy = top + i * row_h + 14
        body.append(text(24, cy + 4.5, r["label"], 13))
        body.append(f'<rect x="{left}" y="{cy - 9}" width="{max(x(r["value"]) - left, 1.5):.1f}" '
                    f'height="18" rx="3" fill="{r["colour"]}"/>')  # fmt: skip
        body.append(f'<line x1="{x(r["low"]):.1f}" y1="{cy}" x2="{x(r["high"]):.1f}" y2="{cy}" '
                    f'stroke="{INK}" stroke-width="1.5"/>')  # fmt: skip
        for edge in (r["low"], r["high"]):
            body.append(f'<line x1="{x(edge):.1f}" y1="{cy - 6}" x2="{x(edge):.1f}" y2="{cy + 6}" '
                        f'stroke="{INK}" stroke-width="1.5"/>')  # fmt: skip
        body.append(text(value_x, cy - 1, f"{r['value']:.1%}", 13, weight=650))
        body.append(text(value_x + 48, cy - 1, r["note"], 12, MUTED))
        body.append(text(value_x, cy + 13, f"95% CI {r['low']:.1%} to {r['high']:.1%}", 11, MUTED))
    body.append(text(24, height - 14, "Source: docs/sample-audits (llama32_3b_x3_baseline, "
                     "llama32_3b_x3_guarded, llama32_3b_guarded_rescored).", 11, MUTED))  # fmt: skip
    desc = "; ".join(f"{r['label']}: {r['value']:.1%} ({r['note']})" for r in rows)
    return svg(width, height, body, "Attack success on llama3.2:3b", desc)


def compas_chart() -> str:
    parity = check("compas", "fairness.group_parity")
    groups = {g["group"]: g for g in parity["details"]["attributes"]["race"]["groups"]}
    names = {"African-American": "Black", "Caucasian": "White"}
    rows = []
    for key, label in (
        ("higher_risk_no_reoffence", ("did not reoffend:", "labelled higher risk")),
        ("lower_risk_reoffended", ("reoffended:", "labelled lower risk")),
    ):
        for group in ("African-American", "Caucasian"):
            g = groups[group]
            ours = 1 - g["tpr"] if key == "higher_risk_no_reoffence" else g["fpr"]
            rows.append(
                (
                    (f"{names[group]} defendants who {label[0]}", label[1]),
                    ours,
                    PROPUBLICA[(group, key)],
                )
            )
    width, left, plot, top, row_h = 900, 310, 470, 92, 50
    scale_max = 0.6
    height = top + row_h * len(rows) + 52

    def x(v: float) -> float:
        return left + plot * v / scale_max

    body = [
        text(24, 30, "COMPAS error rates by race: Pramana against ProPublica's published analysis",
             16, weight=650),
        text(24, 50, "Real risk scores for 6,172 defendants in Broward County, Florida. A decile of "
             "5 to 10 counts as higher risk.", 12, MUTED),
        f'<rect x="{left}" y="62" width="12" height="12" rx="2" fill="{BLUE}"/>',
        text(left + 18, 72.5, "Measured by Pramana", 12),
        f'<rect x="{left + 160}" y="62" width="12" height="12" rx="2" fill="{GREY}"/>',
        text(left + 178, 72.5, "Published by ProPublica (2016)", 12),
    ]  # fmt: skip
    for tick in (0, 0.2, 0.4, 0.6):
        body.append(f'<line x1="{x(tick):.1f}" y1="{top - 6}" x2="{x(tick):.1f}" '
                    f'y2="{top + row_h * len(rows) - 12}" stroke="{GRID}" stroke-width="1"/>')  # fmt: skip
        body.append(text(x(tick), top + row_h * len(rows) + 6, f"{tick:.0%}", 12, MUTED, "middle"))
    for i, (label, ours, published) in enumerate(rows):
        y0 = top + i * row_h
        body.append(text(24, y0 + 12, label[0], 13))
        body.append(text(24, y0 + 28, label[1], 13, MUTED))
        body.append(f'<rect x="{left}" y="{y0 + 2}" width="{x(ours) - left:.1f}" height="14" '
                    f'rx="3" fill="{BLUE}"/>')  # fmt: skip
        body.append(text(x(ours) + 8, y0 + 13.5, f"{ours:.1%}", 12))
        body.append(f'<rect x="{left}" y="{y0 + 19}" width="{x(published) - left:.1f}" height="14" '
                    f'rx="3" fill="{GREY}"/>')  # fmt: skip
        body.append(text(x(published) + 8, y0 + 30.5, f"{published:.1%}", 12, MUTED))
    body.append(text(24, height - 14, "Source: docs/sample-audits/compas and ProPublica, "
                     "'How We Analyzed the COMPAS Recidivism Algorithm'.", 11, MUTED))  # fmt: skip
    desc = "; ".join(
        f"{' '.join(label)}: Pramana {o:.1%}, ProPublica {p:.1%}" for label, o, p in rows
    )
    return svg(width, height, body, "COMPAS error rates by race", desc)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("results-attacks.svg", attack_chart()),
        ("results-compas.svg", compas_chart()),
    ):
        (OUT / name).write_text(content, encoding="utf-8")
        print(f"wrote docs/img/{name}")


if __name__ == "__main__":
    main()
