"""Re-score the recorded real-model runs with the current scorer. No model is called.

Three recordings of the reference assistant on llama3.2:3b (three samples per probe) are
committed with the repository. This script scores those same replies with the current
version of Pramana and writes one audit pack per recording, so the published numbers
always reflect the current scoring rules:

    baseline build, single messages    -> docs/sample-audits/llama32_3b_x3_baseline
    guarded build, single messages     -> docs/sample-audits/llama32_3b_x3_guarded
    guarded build, all attack types    -> docs/sample-audits/llama32_3b_guarded_rescored

Each recording is scored with the probes it actually answered: probes added to the live
set later, and attack types a recording did not include, are left out rather than
counted as failed calls.

    python scripts/rescore_live_run.py
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

from pramana.audit.engine import run_audit
from pramana.reporting import write_outputs
from pramana.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "examples" / "live_assistant"
PACKS = ROOT / "docs" / "sample-audits"
ADDED_AFTER_RECORDING = {"GR-07", "AC-01", "AC-02", "AC-03", "AC-04", "AC-05"}
SINGLE_MESSAGE = ("prompt_injection", "sensitive_disclosure", "groundedness", "policy")


@dataclass(frozen=True)
class Run:
    build: str  # "baseline" or "guarded"
    recording: Path
    out: str
    audit_date: date
    categories: tuple[str, ...] | None  # None: every category in the probe file
    obfuscation: bool


RUNS = [
    Run("baseline", LIVE / "recorded" / "llama32_3b_x3_baseline.json", "llama32_3b_x3_baseline",
        date(2026, 10, 21), SINGLE_MESSAGE, obfuscation=False),
    Run("guarded", LIVE / "recorded" / "llama32_3b_x3_guarded.json", "llama32_3b_x3_guarded",
        date(2026, 10, 21), SINGLE_MESSAGE, obfuscation=False),
    Run("guarded", PACKS / "llama32_3b_guarded_v074" / "llm_replay.jsonl",
        "llama32_3b_guarded_rescored", date(2026, 11, 5), None, obfuscation=True),
]  # fmt: skip


def probes_as_recorded(folder: Path, categories: tuple[str, ...] | None) -> Path:
    data = yaml.safe_load((LIVE / "probes.yaml").read_text(encoding="utf-8"))
    kept = {}
    for category, items in data["probes"].items():
        if categories is not None and category not in categories:
            continue
        items = [p for p in items if p["id"] not in ADDED_AFTER_RECORDING]
        if items:
            kept[category] = items
    data["probes"] = kept
    path = folder / "probes.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    shutil.copy(LIVE / data["sensitive_records"], folder / data["sensitive_records"])
    return path


def rescore(run: Run) -> None:
    out = PACKS / run.out
    with tempfile.TemporaryDirectory() as tmp:
        spec = load_spec(LIVE / f"audit_{run.build}.yaml")
        spec.llm = {
            "mode": "replay",
            "replay": run.recording,
            "probes": probes_as_recorded(Path(tmp), run.categories),
            "knowledge_base": spec.llm["knowledge_base"],
            "samples": 3,
            **({"mutations": spec.llm.get("mutations")} if run.obfuscation else {}),
        }
        if out.exists():
            shutil.rmtree(out)
        result = run_audit(spec, out, audit_date=run.audit_date)
        write_outputs(result, out, ledger=result.ledger)
    llm = ", ".join(
        f"{r.check_id.removeprefix('llm.')} {r.status.value}"
        for r in result.results
        if r.check_id.startswith("llm.") and r.status.value != "skipped"
    )
    print(f"{run.out}: gate {result.gate['decision']}; {llm}")


def main() -> None:
    for run in RUNS:
        rescore(run)


if __name__ == "__main__":
    main()
