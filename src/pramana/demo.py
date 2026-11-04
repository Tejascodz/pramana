"""``pramana demo``: run the bundled case studies straight after ``pip install``.

Each demo is copied into a folder you choose (default ``./pramana-demo``), audited
there, and its evidence pack verified, so a new user sees a full report without
cloning the repository. The case studies plant known defects, so a BLOCK decision
is the expected result.
"""

from __future__ import annotations

import contextlib
import io
import runpy
import shutil
from importlib import resources
from pathlib import Path

DEMOS: dict[str, tuple[str, str]] = {
    "credit": (
        "credit-scoring",
        "Loan pre-approval model: fairness, privacy, drift, EU AI Act tier",
    ),
    "chatbot": ("support-chatbot", "RAG support assistant: prompt injection, PII, made-up figures"),
    "agent": ("agent-traces", "Refund agent: approvals, attribution, misalignment signals"),
}


def _copy_tree(src, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.name == "__pycache__":
            continue
        target = dst / item.name
        if item.is_dir():
            _copy_tree(item, target)
        else:
            target.write_bytes(item.read_bytes())


def prepare(name: str, out_dir: Path) -> Path:
    """Copy one demo into ``out_dir`` and build its inputs. Returns the spec path."""
    folder, _ = DEMOS[name]
    workdir = out_dir / folder
    if workdir.exists():
        shutil.rmtree(workdir / "pack", ignore_errors=True)
    _copy_tree(resources.files("pramana.demos").joinpath(folder), workdir)
    builder = workdir / "build_model.py"
    if builder.exists():
        # The credit case study generates its synthetic data and model locally.
        with contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(builder), run_name="__main__")
    return workdir / "audit.yaml"


def run_demo(names: list[str], out_dir: Path) -> int:
    from pramana.audit.engine import run_audit
    from pramana.audit.ledger import verify_pack
    from pramana.reporting import write_outputs
    from pramana.spec import load_spec

    out_dir = Path(out_dir).resolve()
    for name in names:
        folder, blurb = DEMOS[name]
        print(f"\n> {name}: {blurb}")
        spec = load_spec(prepare(name, out_dir))
        pack = out_dir / folder / "pack"
        result = run_audit(spec, pack)
        paths = write_outputs(result, pack, ledger=result.ledger)
        counts: dict[str, int] = {}
        for r in result.results:
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        ok, _ = verify_pack(pack)
        print(
            "  checks: "
            + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
            + f"\n  gate: {result.gate['decision']}"
            + (
                f" (blocking risks {', '.join(result.gate['blocking_risks'])})"
                if result.gate["blocking_risks"]
                else ""
            )
            + f"\n  evidence pack verified: {'yes' if ok else 'NO'}"
            + f"\n  report: {paths['report']}"
        )
    print(
        "\nThese systems contain planted defects, so BLOCK is the expected decision."
        "\nOpen a report.html in your browser. Check a pack yourself with:"
        f"\n  pramana verify {out_dir / DEMOS[names[0]][0] / 'pack'}"
        "\nStart your own audit with: pramana init my_audit.yaml"
    )
    return 0
