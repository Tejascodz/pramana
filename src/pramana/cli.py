"""Command-line interface.

    pramana run SPEC [--out DIR] [--date YYYY-MM-DD]   run an audit and write the pack
    pramana verify DIR                                 check a pack has not been altered
    pramana summary DIR                                print a Markdown summary of a pack
    pramana classify SPEC                              show the risk classification only
    pramana checks                                     list available checks
    pramana controls [--framework ID] [--markdown]     browse the control library
    pramana init [PATH]                                write a starter audit spec

Exit codes: 0 success, 1 release gate blocked, 2 verification failed, 3 bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from pramana import __version__

EXIT_OK, EXIT_BLOCKED, EXIT_TAMPERED, EXIT_INPUT = 0, 1, 2, 3


def _cmd_run(args: argparse.Namespace) -> int:
    from pramana.audit.engine import run_audit
    from pramana.reporting import write_outputs
    from pramana.spec import SpecError, load_spec
    from pramana.types import Status

    try:
        spec = load_spec(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    out = Path(args.out or f"audit-{spec.system['version']}")
    audit_date = date.fromisoformat(args.date) if args.date else None

    print(f"Pramana {__version__}: auditing {spec.name} v{spec.system['version']}")
    result = run_audit(spec, out, audit_date=audit_date)
    paths = write_outputs(result, out, ledger=result.ledger)

    width = max(len(r.check_id) for r in result.results)
    for r in result.results:
        print(f"  {r.status.value.upper():7} {r.check_id:<{width}}  {r.severity.value}")
    print()
    print(f"Opinion: {result.opinion['rating']}   Gate: {result.gate['decision']}")
    if result.gate["blocking_risks"]:
        print(f"Blocking risks: {', '.join(result.gate['blocking_risks'])}")
    print(f"Evidence root: {result.ledger_root}")
    print(f"Report: {paths['report']}")
    if any(r.status == Status.ERROR for r in result.results):
        print("warning: one or more checks errored; see the report", file=sys.stderr)
    if args.no_gate:
        return EXIT_OK
    return EXIT_BLOCKED if result.gate["decision"] == "BLOCK" else EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    from pramana.audit.ledger import verify_pack

    ok, problems = verify_pack(Path(args.pack))
    if ok:
        print(f"OK: every evidence file and ledger entry in {args.pack} verifies.")
        return EXIT_OK
    print(f"TAMPERED: {len(problems)} problem(s) found in {args.pack}")
    for p in problems:
        print(f"  - {p}")
    return EXIT_TAMPERED


def _cmd_summary(args: argparse.Namespace) -> int:
    path = Path(args.pack) / "results.json"
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return EXIT_INPUT
    data = json.loads(path.read_text(encoding="utf-8"))
    system = data["system"]
    print(f"## Pramana audit: {system['name']} v{system['version']}")
    print()
    print(
        f"**Gate:** {data['gate']['decision']} · **Opinion:** {data['opinion']['rating']} · "
        f"**EU AI Act tier:** {data['classification'].get('eu_tier')} · **Evidence root:** "
        f"`{(data.get('ledger_root') or '')[:16]}`"
    )
    print()
    if data["risks"]:
        print("| Risk | Title | Rating | Owner | Treatment |")
        print("|---|---|---|---|---|")
        for r in data["risks"]:
            print(
                f"| {r['risk_id']} | {r['title']} | {r['rating']} | {r['owner']} | {r['treatment']} |"
            )
    else:
        print("No risks identified.")
    return EXIT_OK


def _cmd_classify(args: argparse.Namespace) -> int:
    from pramana.controls import load_library
    from pramana.risk.classification import classify, obligations
    from pramana.spec import SpecError, load_spec

    try:
        spec = load_spec(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    result = classify(spec.use_case, spec.system_type)
    result.obligations = obligations(result, spec.use_case, load_library(), date.today())
    print(json.dumps(result.to_dict(), indent=2))
    return EXIT_OK


def _cmd_checks(_: argparse.Namespace) -> int:
    from pramana.controls import load_library
    from pramana.registry import all_checks

    lib = load_library()
    for d in all_checks():
        types = ",".join(d.system_types)
        print(f"{d.check_id:36} {d.category:14} [{types}]")
        print(f"{'':36} {lib.crosswalk.get(d.check_id, {}).get('failure_mode', '')}")
    return EXIT_OK


def _cmd_controls(args: argparse.Namespace) -> int:
    from pramana.controls import crosswalk_markdown, load_library

    lib = load_library()
    if args.markdown:
        print(crosswalk_markdown(lib))
        return EXIT_OK
    frameworks = [args.framework] if args.framework else list(lib.frameworks)
    for fid in frameworks:
        if fid not in lib.frameworks:
            print(
                f"error: unknown framework '{fid}'. Known: {', '.join(lib.frameworks)}",
                file=sys.stderr,
            )
            return EXIT_INPUT
        fw = lib.frameworks[fid]
        print(f"{fw.name} ({fw.version}) - {len(fw.controls)} controls")
        for c in fw.controls:
            checks = lib.checks_for_control(c.ref)
            print(f"  {c.id:22} {c.title[:70]:70} {', '.join(checks)}")
        print()
    return EXIT_OK


def _cmd_init(args: argparse.Namespace) -> int:
    from pramana.spec import SPEC_TEMPLATE

    target = Path(args.path)
    if target.exists():
        print(f"error: {target} already exists", file=sys.stderr)
        return EXIT_INPUT
    target.write_text(SPEC_TEMPLATE, encoding="utf-8")
    print(f"Wrote {target}. Edit it, then run: pramana run {target}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pramana",
        description="Pramana: AI Assurance & Evidence Engine.",
    )
    parser.add_argument("--version", action="version", version=f"pramana {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run an audit and write the audit pack")
    run.add_argument("spec", help="path to the audit spec YAML")
    run.add_argument("--out", help="output folder for the audit pack")
    run.add_argument("--date", help="audit date (YYYY-MM-DD); defaults to today")
    run.add_argument(
        "--no-gate", action="store_true", help="always exit 0, even if the gate blocks"
    )
    run.set_defaults(fn=_cmd_run)

    verify = sub.add_parser("verify", help="verify an audit pack has not been altered")
    verify.add_argument("pack", help="audit pack folder")
    verify.set_defaults(fn=_cmd_verify)

    summary = sub.add_parser("summary", help="print a Markdown summary of an audit pack")
    summary.add_argument("pack", help="audit pack folder")
    summary.set_defaults(fn=_cmd_summary)

    classify = sub.add_parser("classify", help="show the risk classification for a spec")
    classify.add_argument("spec")
    classify.set_defaults(fn=_cmd_classify)

    checks = sub.add_parser("checks", help="list available checks")
    checks.set_defaults(fn=_cmd_checks)

    controls = sub.add_parser("controls", help="browse the control library and crosswalk")
    controls.add_argument("--framework", help="NIST, NIST-GAI, ISO42001, EUAIA, INDIA or OWASP-LLM")
    controls.add_argument("--markdown", action="store_true", help="print the crosswalk as Markdown")
    controls.set_defaults(fn=_cmd_controls)

    init = sub.add_parser("init", help="write a starter audit spec")
    init.add_argument("path", nargs="?", default="audit.yaml")
    init.set_defaults(fn=_cmd_init)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
