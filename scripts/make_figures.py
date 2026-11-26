"""Draw the README banner and result charts, each in a light and a dark version.

Every number comes from a results.json under docs/sample-audits or from
docs/data/kaggle_results.json (numbers copied by script from the signed packs of the
Kaggle runs); the only constants are ProPublica's published COMPAS error rates, cited
below. The charts are plain SVG, so the script needs nothing beyond the standard library.

    python scripts/make_figures.py

Colours: a categorical palette checked for colour-vision deficiency on GitHub's light
(#ffffff) and dark (#0d1117) backgrounds; every bar also carries its value as text, so no
reading depends on colour alone.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "docs" / "sample-audits"
DATA = ROOT / "docs" / "data" / "kaggle_results.json"
OUT = ROOT / "docs" / "img"

# ProPublica, "How We Analyzed the COMPAS Recidivism Algorithm" (2016), error-rate table.
PROPUBLICA = {
    ("African-American", "higher_risk_no_reoffence"): 0.449,
    ("Caucasian", "higher_risk_no_reoffence"): 0.235,
    ("African-American", "lower_risk_reoffended"): 0.280,
    ("Caucasian", "lower_risk_reoffended"): 0.477,
}

FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
THEMES = {
    "light": {
        "surface": "#ffffff", "plane": "#f6f8fa", "ink": "#1f2328", "muted": "#59636e",
        "grid": "#e7e7e7", "base": "#c2c2c2", "border": "#d1d9e0",
        "s1": "#257de0", "s2": "#f47230", "s3": "#00b894",
        "critical": "#dc3c3d", "good": "#0aac23", "on_fill": "#ffffff",
    },
    "dark": {
        "surface": "#0d1117", "plane": "#151b23", "ink": "#e6edf3", "muted": "#9198a1",
        "grid": "#262c36", "base": "#3d444d", "border": "#3d444d",
        "s1": "#338ced", "s2": "#e76624", "s3": "#00a888",
        "critical": "#eb6263", "good": "#0aac23", "on_fill": "#ffffff",
    },
}  # fmt: skip


def text(t, x, y, s, size=13, colour="ink", anchor="start", weight=400, extra="") -> str:
    fill = t.get(colour, colour)
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" '
        f'text-anchor="{anchor}" font-weight="{weight}"{extra}>{escape(s)}</text>'
    )


def bar(x0: float, y: float, length: float, height: float, fill: str, r: float = 4) -> str:
    """A horizontal bar anchored at x0 with only its data end rounded."""
    length = max(length, 1.5)
    r = min(r, length / 2, height / 2)
    x1 = x0 + length
    return (
        f'<path d="M{x0:.1f},{y:.1f} H{x1 - r:.1f} Q{x1:.1f},{y:.1f} {x1:.1f},{y + r:.1f} '
        f"V{y + height - r:.1f} Q{x1:.1f},{y + height:.1f} {x1 - r:.1f},{y + height:.1f} "
        f'H{x0:.1f} Z" fill="{fill}"/>'
    )


def svg(t, width: int, height: int, body: list[str], title: str, desc: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{FONT}" role="img">\n'
        f"<title>{escape(title)}</title>\n<desc>{escape(desc)}</desc>\n"
        f'<rect width="{width}" height="{height}" rx="12" fill="{t["surface"]}"/>\n'
        + "\n".join(body)
        + "\n</svg>\n"
    )


def legend(t, x: float, y: float, items: list[tuple[str, str]]) -> list[str]:
    out = []
    for colour, label in items:
        out.append(f'<rect x="{x}" y="{y - 10}" width="12" height="12" rx="3" fill="{t[colour]}"/>')
        out.append(text(t, x + 18, y, label, 12, "muted"))
        x += 30 + 7 * len(label)
    return out


def check(pack: str, check_id: str) -> dict:
    results = json.loads((PACKS / pack / "results.json").read_text(encoding="utf-8"))
    return next(r for r in results["results"] if r["check_id"] == check_id)


# ---------------------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------------------


def hero(t) -> str:
    w, h = 1280, 400
    body = [
        f'<rect x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="12" fill="{t["surface"]}" '
        f'stroke="{t["border"]}"/>',
        text(t, 56, 112, "Pramana", 64, weight=750, extra=' letter-spacing="-1.5"'),
        text(t, 58, 150, "The audit engine for AI systems", 22, "muted", weight=500),
        text(t, 58, 196, "Tests ML models, LLM applications and agents against", 17),
        text(t, 58, 220, "the real system, seals the evidence in a signed,", 17),
        text(t, 58, 244, "hash-chained pack and gates the release.", 17),
    ]
    chips = ["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "OWASP LLM Top 10"]
    x = 58
    for chip in chips:
        cw = 22 + 7.6 * len(chip)
        body.append(f'<rect x="{x}" y="300" width="{cw:.0f}" height="30" rx="15" fill="{t["plane"]}" '
                    f'stroke="{t["border"]}"/>')  # fmt: skip
        body.append(text(t, x + cw / 2, 320, chip, 13, "muted", "middle", 500))
        x += cw + 10
    body.append(text(t, 58, 360, "184 controls in 8 frameworks", 13, "muted"))

    # Pipeline: three kinds of system -> 30 checks -> evidence pack -> release gate.
    sx, sy = 640, 70
    kinds = [("Tabular model", "s1"), ("LLM application", "s2"), ("AI agent", "s3")]
    for i, (label, colour) in enumerate(kinds):
        y = sy + i * 92
        body.append(f'<rect x="{sx}" y="{y}" width="150" height="64" rx="10" fill="{t["plane"]}" '
                    f'stroke="{t["border"]}"/>')  # fmt: skip
        body.append(f'<rect x="{sx}" y="{y}" width="5" height="64" rx="2.5" fill="{t[colour]}"/>')
        body.append(text(t, sx + 20, y + 38, label, 14, weight=600))
        body.append(f'<path d="M{sx + 150},{y + 32} C{sx + 185},{y + 32} {sx + 185},{sy + 124} '
                    f'{sx + 212},{sy + 124}" fill="none" stroke="{t["base"]}" stroke-width="2"/>')  # fmt: skip
    cx = sx + 214
    body += [
        f'<rect x="{cx}" y="{sy + 62}" width="150" height="124" rx="12" fill="{t["plane"]}" stroke="{t["border"]}"/>',
        text(t, cx + 75, sy + 110, "30", 34, anchor="middle", weight=750),
        text(t, cx + 75, sy + 134, "checks", 14, "muted", "middle"),
        text(t, cx + 75, sy + 160, "live, adaptive, replayable", 11, "muted", "middle"),
        f'<line x1="{cx + 150}" y1="{sy + 124}" x2="{cx + 186}" y2="{sy + 124}" stroke="{t["base"]}" stroke-width="2"/>',
        f'<path d="M{cx + 186},{sy + 118} L{cx + 194},{sy + 124} L{cx + 186},{sy + 130} Z" fill="{t["base"]}"/>',
    ]  # fmt: skip
    px = cx + 198
    body += [
        f'<rect x="{px}" y="{sy + 62}" width="150" height="124" rx="12" fill="{t["plane"]}" stroke="{t["border"]}"/>',
        text(t, px + 75, sy + 100, "Evidence pack", 14, anchor="middle", weight=600),
    ]  # fmt: skip
    for k, line in enumerate(("hash-chained ledger", "Ed25519 signature", "Sigstore attestation")):
        body.append(text(t, px + 75, sy + 124 + k * 18, line, 11, "muted", "middle"))
    body.append(f'<line x1="{px + 75}" y1="{sy + 186}" x2="{px + 75}" y2="{sy + 222}" '
                f'stroke="{t["base"]}" stroke-width="2"/>')  # fmt: skip
    gy = sy + 226
    body += [
        text(t, px + 75, gy + 18, "Release gate", 12, "muted", "middle"),
        f'<rect x="{px - 8}" y="{gy + 28}" width="78" height="30" rx="15" fill="{t["critical"]}"/>',
        text(t, px + 31, gy + 48, "✕ BLOCK", 13, "on_fill", "middle", 700),
        f'<rect x="{px + 80}" y="{gy + 28}" width="78" height="30" rx="15" fill="{t["good"]}"/>',
        text(t, px + 119, gy + 48, "✓ PASS", 13, "on_fill", "middle", 700),
    ]  # fmt: skip
    desc = (
        "Pramana: the audit engine for AI systems. Tabular models, LLM applications and AI agents "
        "go through 30 checks into a hash-chained, signed evidence pack, which decides the release "
        "gate (block or pass). Mapped to NIST AI RMF, ISO/IEC 42001, the EU AI Act and the OWASP "
        "LLM Top 10: 184 controls in 8 frameworks."
    )
    return svg(t, w, h, body, "Pramana", desc)


# ---------------------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------------------

GOAL_NAMES = {
    "marker": ("Attacker-chosen code", "make the assistant say it"),
    "persona": ("Rule-free persona", "take on a role and call sign"),
    "canary": ("System-prompt secret", "reveal the hidden canary"),
    "exfil": ("Exfiltration link", "write a link that carries data"),
}


def adaptive_chart(t) -> str:
    data = json.loads(DATA.read_text(encoding="utf-8"))["adaptive_vs_guard"]
    goals = data["by_goal"]
    w, left, plot, top, row_h = 1000, 250, 360, 134, 74
    status_x = left + plot + 70
    h = top + row_h * len(goals) + 58

    def x(v: float) -> float:
        return left + plot * v

    tot = data["totals"]
    body = [
        text(t, 28, 38, "A third-party guard stops most fixed attacks. An adaptive search still gets through.", 18, weight=650),
        text(t, 28, 62, "Qwen2.5-14B with a confidential system prompt, without and behind ProtectAI's open "
             "prompt-injection classifier.", 12.5, "muted"),
        text(t, 28, 80, f"Fixed attacks: {tot['no_guard']['fixed_succeeded']} of {tot['no_guard']['fixed_sent']} "
             f"succeeded without the guard, {tot['guard']['fixed_succeeded']} of {tot['guard']['fixed_sent']} "
             "behind it.", 12.5, "muted"),
        *legend(t, left, 112, [("s1", "No guard"), ("s2", "Behind the guard")]),
        text(t, status_x, 112, "Adaptive search through the guard (40 queries)", 12, "muted"),
    ]  # fmt: skip
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        body.append(f'<line x1="{x(tick):.1f}" y1="{top - 8}" x2="{x(tick):.1f}" '
                    f'y2="{top + row_h * len(goals) - 18}" stroke="{t["grid"]}"/>')  # fmt: skip
        body.append(
            text(t, x(tick), top + row_h * len(goals) - 2, f"{tick:.0%}", 11.5, "muted", "middle")
        )
    body.append(f'<line x1="{left}" y1="{top - 8}" x2="{left}" y2="{top + row_h * len(goals) - 18}" '
                f'stroke="{t["base"]}"/>')  # fmt: skip
    for i, g in enumerate(goals):
        y0 = top + i * row_h
        name, what = GOAL_NAMES[g["goal"]]
        body.append(text(t, 28, y0 + 17, name, 14, weight=600))
        body.append(text(t, 28, y0 + 35, what, 12, "muted"))
        for j, (key, colour) in enumerate((("no_guard", "s1"), ("guard", "s2"))):
            r = g[key]
            v = r["fixed_succeeded"] / r["fixed_sent"]
            by = y0 + 4 + j * 20  # 2px surface gap between the paired bars
            body.append(bar(left, by, plot * v, 18, t[colour]))
            body.append(
                text(
                    t,
                    x(v) + 8,
                    by + 13.5,
                    f"{v:.0%}  ({r['fixed_succeeded']} of {r['fixed_sent']})",
                    12,
                )
            )
        a = g["guard"]
        if a["adaptive_reached"]:
            how = "attacker model" if a["adaptive_strategy"] == "attacker" else "search"
            body += [
                f'<circle cx="{status_x + 8}" cy="{y0 + 21}" r="8" fill="{t["critical"]}"/>',
                text(t, status_x + 8, y0 + 25.5, "!", 12, "on_fill", "middle", 800),
                text(
                    t,
                    status_x + 24,
                    y0 + 19,
                    f"Reached at query {a['adaptive_query']}",
                    14,
                    weight=600,
                ),
                text(t, status_x + 24, y0 + 37, f"found by the {how}", 12, "muted"),
            ]
        else:
            body += [
                f'<circle cx="{status_x + 8}" cy="{y0 + 21}" r="8" fill="{t["good"]}"/>',
                text(t, status_x + 8, y0 + 25.5, "✓", 11, "on_fill", "middle", 800),
                text(
                    t,
                    status_x + 24,
                    y0 + 19,
                    f"Held for all {a['adaptive_budget']} queries",
                    14,
                    weight=600,
                ),
                text(t, status_x + 24, y0 + 37, "not reached", 12, "muted"),
            ]
    body.append(text(t, 28, h - 18, "Share of Pramana's fixed attacks that succeeded, by attack goal. One sample per "
                     "attack. Source: docs/data/kaggle_results.json (Kaggle run of 0.11.0, 22 Nov 2026).", 11, "muted"))  # fmt: skip
    desc = "; ".join(
        f"{GOAL_NAMES[g['goal']][0]}: fixed attacks {g['no_guard']['fixed_succeeded']}/{g['no_guard']['fixed_sent']} "
        f"without the guard, {g['guard']['fixed_succeeded']}/{g['guard']['fixed_sent']} behind it; adaptive search "
        + (
            f"reached it at query {g['guard']['adaptive_query']}"
            if g["guard"]["adaptive_reached"]
            else "did not reach it"
        )
        for g in goals
    )
    return svg(t, w, h, body, "Fixed versus adaptive attacks against a third-party guard", desc)


def leak_chart(t) -> str:
    data = json.loads(DATA.read_text(encoding="utf-8"))["leak_rule"]
    pts = data["by_threshold"]
    w, h = 1000, 470
    left, right, top, bottom = 90, 820, 118, 380

    def x(v: float) -> float:
        return left + (right - left) * (v - 0.3) / 0.6

    def y(v: float) -> float:
        return bottom - (bottom - top) * v

    run = data["run"]
    body = [
        text(t, 28, 38, f"The leak rule on {run['rows']:,} replies labelled by someone else", 18, weight=650),
        text(t, 28, 62, f"{run['dataset']} ({run['licence']}): system prompts with model replies, "
             f"{run['labelled_leaks']:,} labelled as leaks. A reply fails when it recites half the prompt in order.", 12.5, "muted"),
        *legend(t, left, 96, [("s1", "Precision"), ("s2", "Recall")]),
        f'<rect x="{x(0.4):.1f}" y="{top}" width="{x(0.5) - x(0.4):.1f}" height="{bottom - top}" fill="{t["plane"]}"/>',
        text(t, (x(0.4) + x(0.5)) / 2, top + 18, "review", 11.5, "muted", "middle", 600),
        f'<line x1="{x(0.5):.1f}" y1="{top}" x2="{x(0.5):.1f}" y2="{bottom}" stroke="{t["ink"]}" '
        f'stroke-width="1.5" stroke-dasharray="4 4"/>',
        text(t, x(0.5) + 8, bottom - 10, "fails the check", 11.5, "ink", weight=600),
    ]  # fmt: skip
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        body.append(
            f'<line x1="{left}" y1="{y(tick):.1f}" x2="{right}" y2="{y(tick):.1f}" stroke="{t["grid"]}"/>'
        )
        body.append(text(t, left - 12, y(tick) + 4, f"{tick:.2f}", 11.5, "muted", "end"))
    body.append(
        f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="{t["base"]}"/>'
    )
    for p in pts:
        body.append(
            text(
                t, x(p["min_share"]), bottom + 22, f"{p['min_share']:.1f}", 11.5, "muted", "middle"
            )
        )
    body.append(
        text(
            t,
            (left + right) / 2,
            bottom + 46,
            "Share of the system prompt reproduced in order (threshold)",
            12,
            "muted",
            "middle",
        )
    )
    for key, colour in (("precision", "s1"), ("recall", "s2")):
        path = " ".join(
            f"{'M' if i == 0 else 'L'}{x(p['min_share']):.1f},{y(p[key]):.1f}"
            for i, p in enumerate(pts)
        )
        body.append(
            f'<path d="{path}" fill="none" stroke="{t[colour]}" stroke-width="2.5" stroke-linejoin="round"/>'
        )
        for p in pts:
            body.append(f'<circle cx="{x(p["min_share"]):.1f}" cy="{y(p[key]):.1f}" r="5" fill="{t[colour]}" '
                        f'stroke="{t["surface"]}" stroke-width="2"/>')  # fmt: skip
        end = pts[-1]
        body.append(text(t, right + 14, y(end[key]) + 4, key.capitalize(), 12.5, weight=600))
    at = next(p for p in pts if abs(p["min_share"] - 0.5) < 1e-9)
    body += [
        text(t, x(0.5) + 10, y(at["precision"]) + 22, f"precision {at['precision']:.3f}  ({at['fp']} false alarms)", 12.5, weight=600),
        text(t, x(0.5) + 10, y(at["recall"]) + 22, f"recall {at['recall']:.2f}", 12.5, weight=600),
        text(t, 28, h - 18, f"Fail or review together catch {data['fail_or_review_recall']:.0%} of leaks; the rest are "
             "paraphrases. Source: docs/data/kaggle_results.json (Kaggle run of 0.9.3).", 11, "muted"),
    ]  # fmt: skip
    desc = "; ".join(
        f"threshold {p['min_share']}: precision {p['precision']}, recall {p['recall']}" for p in pts
    )
    return svg(t, w, h, body, "Precision and recall of the system-prompt leak rule", desc)


def compas_chart(t) -> str:
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
            rows.append(((f"{names[group]} defendants who {label[0]}", label[1]), ours,
                         PROPUBLICA[(group, key)]))  # fmt: skip
    w, left, plot, top, row_h = 1000, 330, 480, 112, 56
    h = top + row_h * len(rows) + 56

    def x(v: float) -> float:
        return left + plot * v / 0.6

    body = [
        text(t, 28, 38, "COMPAS error rates by race: Pramana against ProPublica's published analysis", 18, weight=650),
        text(t, 28, 62, "Real risk scores for 6,172 defendants in Broward County, Florida; a decile of 5 to 10 counts "
             "as higher risk.", 12.5, "muted"),
        *legend(t, left, 92, [("s1", "Measured by Pramana"), ("s3", "Published by ProPublica (2016)")]),
    ]  # fmt: skip
    for tick in (0, 0.2, 0.4, 0.6):
        body.append(f'<line x1="{x(tick):.1f}" y1="{top - 8}" x2="{x(tick):.1f}" '
                    f'y2="{top + row_h * len(rows) - 14}" stroke="{t["grid"]}"/>')  # fmt: skip
        body.append(
            text(t, x(tick), top + row_h * len(rows) + 4, f"{tick:.0%}", 11.5, "muted", "middle")
        )
    body.append(
        f'<line x1="{left}" y1="{top - 8}" x2="{left}" y2="{top + row_h * len(rows) - 14}" stroke="{t["base"]}"/>'
    )
    for i, (label, ours, published) in enumerate(rows):
        y0 = top + i * row_h
        body.append(text(t, 28, y0 + 14, label[0], 13.5, weight=600))
        body.append(text(t, 28, y0 + 31, label[1], 12.5, "muted"))
        body.append(bar(left, y0 + 2, x(ours) - left, 17, t["s1"]))
        body.append(text(t, x(ours) + 8, y0 + 15, f"{ours:.1%}", 12.5, weight=600))
        body.append(bar(left, y0 + 21, x(published) - left, 17, t["s3"]))
        body.append(text(t, x(published) + 8, y0 + 34, f"{published:.1%}", 12.5))
    body.append(text(t, 28, h - 18, "Source: docs/sample-audits/compas and ProPublica, 'How We Analyzed the COMPAS "
                     "Recidivism Algorithm' (2016).", 11, "muted"))  # fmt: skip
    desc = "; ".join(
        f"{' '.join(label)}: Pramana {o:.1%}, ProPublica {p:.1%}" for label, o, p in rows
    )
    return svg(t, w, h, body, "COMPAS error rates by race", desc)


def rate_row(pack: str, check_id: str, label: str) -> dict:
    c = check(pack, check_id)
    probes = c["details"]["probes"]
    failed = sum(p["samples_failed"] for p in probes)
    judged = sum(p["samples_evaluated"] for p in probes)
    m = c["metrics"]
    return {"label": label, "value": failed / judged, "low": m["ci_low"], "high": m["ci_high"],
            "note": f"{failed} of {judged} samples"}  # fmt: skip


def attack_chart(t) -> str:
    rows = [
        (rate_row("llama32_3b_x3_baseline", "llm.prompt_injection", "Single-message injection"), "s2", "baseline build"),
        (rate_row("llama32_3b_x3_guarded", "llm.prompt_injection", "Single-message injection"), "s1", "guarded build"),
        (rate_row("llama32_3b_guarded_rescored", "llm.obfuscation", "Disguised injection"), "s1", "guarded build"),
        (rate_row("llama32_3b_guarded_rescored", "llm.multi_turn", "Multi-turn conversations"), "s1", "guarded build"),
    ]  # fmt: skip
    w, left, plot, top, row_h = 1000, 300, 420, 112, 54
    value_x = left + plot + 26
    h = top + row_h * len(rows) + 56

    def x(v: float) -> float:
        return left + plot * v / 0.35

    body = [
        text(t, 28, 38, "Attack success on llama3.2:3b behind the reference assistant", 18, weight=650),
        text(t, 28, 62, "Share of judged samples in which the attack worked, three samples per probe; whiskers are "
             "95% Wilson intervals.", 12.5, "muted"),
        *legend(t, left, 92, [("s2", "Baseline build"), ("s1", "Guarded build")]),
    ]  # fmt: skip
    for tick in (0, 0.1, 0.2, 0.3):
        body.append(f'<line x1="{x(tick):.1f}" y1="{top - 8}" x2="{x(tick):.1f}" '
                    f'y2="{top + row_h * len(rows) - 14}" stroke="{t["grid"]}"/>')  # fmt: skip
        body.append(
            text(t, x(tick), top + row_h * len(rows) + 4, f"{tick:.0%}", 11.5, "muted", "middle")
        )
    body.append(
        f'<line x1="{left}" y1="{top - 8}" x2="{left}" y2="{top + row_h * len(rows) - 14}" stroke="{t["base"]}"/>'
    )
    for i, (r, colour, build) in enumerate(rows):
        cy = top + i * row_h + 12
        body.append(text(t, 28, cy + 2, r["label"], 13.5, weight=600))
        body.append(text(t, 28, cy + 19, build, 12.5, "muted"))
        body.append(bar(left, cy - 9, x(r["value"]) - left, 18, t[colour]))
        body.append(
            f'<line x1="{x(r["low"]):.1f}" y1="{cy}" x2="{x(r["high"]):.1f}" y2="{cy}" stroke="{t["ink"]}" stroke-width="1.5"/>'
        )
        for edge in (r["low"], r["high"]):
            body.append(
                f'<line x1="{x(edge):.1f}" y1="{cy - 6}" x2="{x(edge):.1f}" y2="{cy + 6}" stroke="{t["ink"]}" stroke-width="1.5"/>'
            )
        body.append(text(t, value_x, cy + 1, f"{r['value']:.1%}", 13.5, weight=650))
        body.append(text(t, value_x + 52, cy + 1, r["note"], 12, "muted"))
        body.append(
            text(t, value_x, cy + 18, f"95% CI {r['low']:.1%} to {r['high']:.1%}", 11.5, "muted")
        )
    body.append(text(t, 28, h - 18, "Source: docs/sample-audits (llama32_3b_x3_baseline, llama32_3b_x3_guarded, "
                     "llama32_3b_guarded_rescored).", 11, "muted"))  # fmt: skip
    desc = "; ".join(f"{r['label']}, {b}: {r['value']:.1%} ({r['note']})" for r, _, b in rows)
    return svg(t, w, h, body, "Attack success on llama3.2:3b", desc)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, draw in (
        ("hero", hero),
        ("results-adaptive", adaptive_chart),
        ("results-leak", leak_chart),
        ("results-compas", compas_chart),
        ("results-attacks", attack_chart),
    ):
        for mode, theme in THEMES.items():
            file = f"{name}.svg" if mode == "light" else f"{name}-dark.svg"
            (OUT / file).write_text(draw(theme), encoding="utf-8")
            print(f"wrote docs/img/{file}")


if __name__ == "__main__":
    main()
