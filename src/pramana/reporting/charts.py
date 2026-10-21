"""Inline SVG charts for the HTML report.

Charts are plain SVG strings styled through CSS custom properties defined in the
report template, so they follow light/dark mode, print cleanly and need no
JavaScript. Every mark carries a <title> so values show on hover, and every
chart has a matching table elsewhere in the report.
"""

from __future__ import annotations

from html import escape
from typing import Any

STATE_CLASS = {
    "evidenced": "st-good",
    "partial": "st-warn",
    "deficient": "st-crit",
    "not tested": "st-none",
}
STATE_ORDER = ["evidenced", "partial", "deficient", "not tested"]


def coverage_bars(frameworks: dict[str, Any]) -> str:
    rows = [
        (fid, fw) for fid, fw in frameworks.items() if sum(fw["totals"][s] for s in STATE_ORDER) > 0
    ]
    label_w, bar_w, row_h, gap = 250, 470, 24, 12
    width = label_w + bar_w + 120
    height = len(rows) * (row_h + gap) + 8
    parts = [
        f'<svg class="chart coverage" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Control coverage by framework">'
    ]
    for i, (_, fw) in enumerate(rows):
        y = 4 + i * (row_h + gap)
        totals = fw["totals"]
        applicable = sum(totals[s] for s in STATE_ORDER)
        parts.append(
            f'<text class="t-label" x="{label_w - 12}" y="{y + row_h / 2 + 4}" text-anchor="end">'
            f"{escape(fw['name'])}</text>"
        )
        x = float(label_w)
        for state in STATE_ORDER:
            n = totals[state]
            if not n:
                continue
            w = bar_w * n / applicable
            seg_w = max(w - 2, 1)
            parts.append(
                f'<rect class="{STATE_CLASS[state]}" x="{x:.1f}" y="{y}" width="{seg_w:.1f}" '
                f'height="{row_h}" rx="3"><title>{escape(fw["name"])}: {n} {state}</title></rect>'
            )
            if w > 26:
                parts.append(
                    f'<text class="t-on-bar" x="{x + seg_w / 2:.1f}" y="{y + row_h / 2 + 4}" '
                    f'text-anchor="middle">{n}</text>'
                )
            x += w
        done = totals["evidenced"]
        parts.append(
            f'<text class="t-muted" x="{label_w + bar_w + 10}" y="{y + row_h / 2 + 4}">'
            f"{done}/{applicable} evidenced</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def group_bars(groups: list[dict[str, Any]], title: str, threshold_ratio: float = 0.8) -> str:
    usable = [g for g in groups if g.get("adequate_sample", True)]
    if not usable:
        return ""
    width, height = 560, 268
    left, right, top, bottom = 48, 16, 38, 56
    plot_w, plot_h = width - left - right, height - top - bottom
    top_rate = max(g["selection_rate"] for g in usable)
    ref = top_rate * threshold_ratio
    slot = plot_w / len(usable)
    bar_w = min(56, slot * 0.6)

    def y_of(v: float) -> float:
        return top + plot_h * (1 - v)

    parts = [
        f'<svg class="chart bars" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{escape(title)}">',
        f'<line class="ref" x1="{left}" x2="{left + 28}" y1="12" y2="12"/>',
        f'<text class="t-ref" x="{left + 36}" y="16">four-fifths of the most favoured group '
        f"({ref:.0%})</text>",
    ]
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        y = y_of(tick)
        parts.append(
            f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="t-muted" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">'
            f"{tick:.0%}</text>"
        )
    for i, g in enumerate(usable):
        cx = left + slot * i + slot / 2
        y = y_of(g["selection_rate"])
        flagged = g["selection_rate"] < ref
        x0, x1, base = cx - bar_w / 2, cx + bar_w / 2, top + plot_h
        if base - y > 4:
            parts.append(
                f'<path class="{"bar-flag" if flagged else "bar"}" '
                f'd="M{x0:.1f},{base:.1f} V{y + 4:.1f} Q{x0:.1f},{y:.1f} {x0 + 4:.1f},{y:.1f} '
                f'H{x1 - 4:.1f} Q{x1:.1f},{y:.1f} {x1:.1f},{y + 4:.1f} V{base:.1f} Z">'
                f"<title>{escape(g['group'])}: {g['selection_rate']:.1%} favourable "
                f"(n={g['n']})</title></path>"
            )
        inside = base - y > 24
        label_y = y + 17 if inside else y - 6
        value_cls = ("t-in-flag" if flagged else "t-in-bar") if inside else "t-value"
        parts.append(
            f'<text class="{value_cls}" x="{cx:.1f}" y="{label_y:.1f}" text-anchor="middle">'
            f"{g['selection_rate']:.0%}</text>"
        )
        label = g["group"] if len(g["group"]) <= 16 else g["group"][:15] + "…"
        parts.append(
            f'<text class="t-label" x="{cx:.1f}" y="{base + 18}" text-anchor="middle">'
            f"{escape(label)}</text>"
        )
        parts.append(
            f'<text class="t-muted" x="{cx:.1f}" y="{base + 34}" text-anchor="middle">'
            f"n={g['n']}</text>"
        )
    ry = y_of(ref)
    parts.append(
        f'<line class="ref" x1="{left}" x2="{width - right}" y1="{ry:.1f}" y2="{ry:.1f}"/>'
    )
    parts.append("</svg>")
    return "".join(parts)


def risk_heatmap(risks: list[dict[str, Any]]) -> str:
    cell, left, top = 64, 70, 16
    width, height = left + cell * 5 + 16, top + cell * 5 + 52
    by_cell: dict[tuple[int, int], list[str]] = {}
    for r in risks:
        by_cell.setdefault((r["likelihood"], r["impact"]), []).append(
            r["risk_id"] + ("*" if r.get("accepted") else "")
        )
    parts = [
        f'<svg class="chart heat" viewBox="0 0 {width} {height}" role="img" aria-label="Risk heat map">'
    ]
    for impact in range(5, 0, -1):
        for likelihood in range(1, 6):
            score = impact * likelihood
            band = (
                "crit" if score >= 20 else "high" if score >= 12 else "med" if score >= 6 else "low"
            )
            x = left + (likelihood - 1) * cell
            y = top + (5 - impact) * cell
            ids = by_cell.get((likelihood, impact), [])
            parts.append(
                f'<rect class="hm-{band}" x="{x + 1}" y="{y + 1}" width="{cell - 2}" height="{cell - 2}" rx="4">'
                f"<title>Likelihood {likelihood} × impact {impact} = {score}"
                f"{': ' + ', '.join(ids) if ids else ''}</title></rect>"
            )
            shown = ids if len(ids) <= 4 else ids[:3]
            for j, rid in enumerate(shown):
                parts.append(
                    f'<text class="hm-id" x="{x + cell / 2}" y="{y + 17 + j * 13}" text-anchor="middle">{escape(rid)}</text>'
                )
            if len(ids) > 4:
                parts.append(
                    f'<text class="hm-id" x="{x + cell / 2}" y="{y + 17 + 3 * 13}" text-anchor="middle">+{len(ids) - 3} more</text>'
                )
    for i in range(1, 6):
        parts.append(
            f'<text class="t-muted" x="{left + (i - 0.5) * cell}" y="{top + 5 * cell + 16}" text-anchor="middle">{i}</text>'
        )
        parts.append(
            f'<text class="t-muted" x="{left - 10}" y="{top + (5 - i + 0.5) * cell + 4}" text-anchor="end">{i}</text>'
        )
    parts.append(
        f'<text class="t-label" x="{left + 2.5 * cell}" y="{top + 5 * cell + 38}" text-anchor="middle">Likelihood</text>'
    )
    parts.append(
        f'<text class="t-label" x="16" y="{top + 2.5 * cell}" text-anchor="middle" '
        f'transform="rotate(-90 16 {top + 2.5 * cell})">Impact</text>'
    )
    parts.append("</svg>")
    return "".join(parts)
