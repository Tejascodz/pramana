"""Command-line interface.

    pramana run SPEC [--out DIR] [--date D] [--samples N]  run an audit, write the pack
    pramana verify DIR                                 check a pack has not been altered
    pramana summary DIR                                print a Markdown summary of a pack
    pramana ping SPEC                                  check the LLM endpoint is reachable
    pramana diff OLD NEW [--fail-on-regression]        compare two audit packs
    pramana classify SPEC                              show the risk classification only
    pramana checks                                     list available checks
    pramana controls [--framework ID] [--markdown]     browse the control library
    pramana init [PATH]                                write a starter audit spec

Exit codes: 0 success, 1 release gate blocked, 2 verification failed, 3 bad input,
4 endpoint unreachable.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from pramana import __version__

EXIT_OK, EXIT_BLOCKED, EXIT_TAMPERED, EXIT_INPUT, EXIT_UNREACHABLE = 0, 1, 2, 3, 4


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
    if args.replay:
        if not spec.llm:
            print("error: --replay needs a spec with an 'llm' section", file=sys.stderr)
            return EXIT_INPUT
        keep = ("probes", "knowledge_base", "include_knowledge_base", "samples")
        spec.llm = {
            "mode": "replay",
            "replay": Path(args.replay),
            **{k: spec.llm[k] for k in keep if k in spec.llm},
        }
    if args.samples:
        spec.llm["samples"] = args.samples
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
    if result.gate.get("incomplete_checks"):
        print(f"Incomplete checks: {', '.join(result.gate['incomplete_checks'])}")
    if result.llm_run.get("calls"):
        run = result.llm_run
        p50 = run.get("latency_p50_ms")
        print(
            f"LLM calls: {run['calls']} ({run['errors']} failed)"
            + (
                f", p50 latency {p50 / 1000:.1f}s"
                if p50 and p50 >= 1000
                else f", p50 latency {p50:.0f} ms"
                if p50
                else ""
            )
            + (f", model {', '.join(run['models_reported'])}" if run.get("models_reported") else "")
        )
    print(f"Evidence root: {result.ledger_root}")
    print(f"Report: {paths['report']}")
    if any(r.status == Status.ERROR for r in result.results):
        print("warning: one or more checks errored; see the report", file=sys.stderr)
    if args.no_gate:
        return EXIT_OK
    return EXIT_BLOCKED if result.gate["decision"] == "BLOCK" else EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    from pramana.audit.ledger import SIGNATURE_NAME_IF_ANY, verify_pack

    ok, problems = verify_pack(Path(args.pack))
    if not ok:
        print(f"TAMPERED: {len(problems)} problem(s) found in {args.pack}")
        for p in problems:
            print(f"  - {p}")
        return EXIT_TAMPERED

    signed = (Path(args.pack) / SIGNATURE_NAME_IF_ANY).exists()
    if getattr(args, "require_signature", False) or getattr(args, "public_key", None) or signed:
        from pramana.audit.signing import SigningError, verify_pack_signature

        if not signed and getattr(args, "require_signature", False):
            print(f"UNSIGNED: {args.pack} has no signature but --require-signature was given")
            return EXIT_TAMPERED
        key = Path(args.public_key).read_bytes() if getattr(args, "public_key", None) else None
        try:
            sok, sproblems = verify_pack_signature(Path(args.pack), key)
        except SigningError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INPUT
        if not sok:
            print(f"SIGNATURE INVALID: {len(sproblems)} problem(s) in {args.pack}")
            for p in sproblems:
                print(f"  - {p}")
            return EXIT_TAMPERED
        print(f"OK: {args.pack} verifies and its signature is valid.")
        return EXIT_OK

    print(f"OK: every evidence file and ledger entry in {args.pack} verifies.")
    return EXIT_OK


def _cmd_keygen(args: argparse.Namespace) -> int:
    import os

    from pramana.audit.signing import SigningError, generate_keypair

    try:
        private_pem, public_pem = generate_keypair()
    except SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv, pub = out / "pramana_ed25519.key", out / "pramana_ed25519.pub"
    priv.write_bytes(private_pem)
    os.chmod(priv, 0o600)
    pub.write_bytes(public_pem)
    print(f"Wrote private key {priv} (keep secret) and public key {pub} (share for verification).")
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    from pramana.audit.signing import SigningError, sign_pack

    try:
        sign_pack(Path(args.pack), Path(args.key).read_bytes())
    except (SigningError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    print(
        f"Signed {args.pack}. Share the pack and your public key; verify with: pramana verify {args.pack}"
    )
    return EXIT_OK


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


KEY_METRICS = (
    "attack_success_rate", "sample_attack_success_rate", "disclosures", "groundedness", "breaches",
    "auc", "ece", "di_residence", "di_gender", "score_psi", "attack_auc", "completeness",
    "auditability_index", "error_rate", "latency_p95_ms",
)  # fmt: skip


def _load_results(pack: str) -> dict | None:
    path = Path(pack) / "results.json"
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _cmd_diff(args: argparse.Namespace) -> int:
    old, new = _load_results(args.old), _load_results(args.new)
    if old is None or new is None:
        return EXIT_INPUT
    label_old = f"{old['system']['name']} v{old['system']['version']}"
    label_new = f"{new['system']['name']} v{new['system']['version']}"
    print(f"## Pramana diff\n\n**Before:** {label_old}  \n**After:** {label_new}\n")
    print("| | Before | After |\n|---|---|---|")
    print(f"| Release gate | {old['gate']['decision']} | {new['gate']['decision']} |")
    print(f"| Audit opinion | {old['opinion']['rating']} | {new['opinion']['rating']} |")

    def count(d: dict, ratings: tuple[str, ...]) -> int:
        return sum(1 for r in d["risks"] if not r["accepted"] and r["rating"] in ratings)

    print(
        f"| Open high/critical risks | {count(old, ('high', 'critical'))} | {count(new, ('high', 'critical'))} |"
    )
    print(
        f"| Open risks (all) | {count(old, ('critical', 'high', 'medium', 'low', 'info'))} | {count(new, ('critical', 'high', 'medium', 'low', 'info'))} |\n"
    )

    before = {r["check_id"]: r for r in old["results"]}
    after = {r["check_id"]: r for r in new["results"]}
    order = {"pass": 0, "skipped": 1, "warn": 2, "error": 3, "fail": 4}  # nosec B105 - statuses
    print("| Check | Before | After | Change | Key metrics |\n|---|---|---|---|---|")
    improved = regressed = 0
    for check_id in list(dict.fromkeys([*before, *after])):
        b, a = before.get(check_id), after.get(check_id)
        sb, sa = (b or {}).get("status", "-"), (a or {}).get("status", "-")
        if sb in order and sa in order and order[sa] < order[sb]:
            change, improved = "improved", improved + 1
        elif sb in order and sa in order and order[sa] > order[sb]:
            change, regressed = "**regressed**", regressed + 1
        else:
            change = ""
        metrics = []
        for key in KEY_METRICS:
            vb, va = (b or {}).get("metrics", {}).get(key), (a or {}).get("metrics", {}).get(key)
            if vb is not None or va is not None:
                if vb != va:
                    metrics.append(f"{key} {vb} → {va}")
        print(f"| `{check_id}` | {sb} | {sa} | {change} | {'; '.join(metrics[:3])} |")
    print(f"\n{improved} check(s) improved, {regressed} regressed.")
    return EXIT_BLOCKED if regressed and args.fail_on_regression else EXIT_OK


def _cmd_ping(args: argparse.Namespace) -> int:
    from pramana.context import AuditContext
    from pramana.spec import SpecError, load_spec

    try:
        spec = load_spec(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    if not spec.llm:
        print("error: this spec has no 'llm' section", file=sys.stderr)
        return EXIT_INPUT
    ctx = AuditContext(spec)
    try:
        info = ctx.llm_client.describe()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    print(f"Target: {info.get('endpoint') or info.get('source')} ({info['mode']})")
    if not ctx.llm_is_live:
        print("Replay mode: no network call needed.")
        return EXIT_OK
    reply = ctx.llm_client.complete(
        ctx.system_prompt, "Hello. Please reply with one short sentence."
    )
    if not reply.ok:
        print(f"UNREACHABLE: {reply.error}")
        return EXIT_UNREACHABLE
    print(f"OK in {reply.latency_ms / 1000:.1f}s, model {reply.model or 'not reported'}")
    print(f"Reply: {reply.text[:160]}")
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


def _cmd_scan_trace(args: argparse.Namespace) -> int:
    from pramana.adapters.traces import stream_events
    from pramana.checks.agent_trace import scan_misalignment

    source = Path(args.source)
    if not source.exists():
        print(f"error: {source} not found", file=sys.stderr)
        return EXIT_INPUT

    counts: dict[str, int] = {}
    total = events = 0
    out = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    try:
        # One event at a time: constant memory regardless of trace size.
        for event in stream_events(source, args.format):
            events += 1
            for signal in scan_misalignment([event]):
                total += 1
                counts[signal["pattern"]] = counts.get(signal["pattern"], 0) + 1
                line = json.dumps(signal, ensure_ascii=False)
                if out:
                    out.write(line + "\n")
                else:
                    print(line)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: could not stream {source} as {args.format}: {exc}", file=sys.stderr)
        return EXIT_INPUT
    finally:
        if out:
            out.close()

    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"
    print(f"Scanned {events} events; {total} misalignment signal(s): {summary}.", file=sys.stderr)
    if total and args.fail_on_signal:
        return EXIT_BLOCKED
    return EXIT_OK


def _cmd_ingest(args: argparse.Namespace) -> int:
    from pramana.adapters.traces import load_trace

    source = Path(args.source)
    if not source.exists():
        print(f"error: {source} not found", file=sys.stderr)
        return EXIT_INPUT
    try:
        events = load_trace(source, args.format)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: could not read {source} as {args.format}: {exc}", file=sys.stderr)
        return EXIT_INPUT
    lines = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
    if args.out:
        Path(args.out).write_text(lines + "\n", encoding="utf-8")
        print(f"Wrote {len(events)} events to {args.out}. Point your spec's agent.trace at it.")
    else:
        print(lines)
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
    run.add_argument("--samples", type=int, help="override llm.samples (times each probe is sent)")
    run.add_argument(
        "--replay", help="re-score a recorded llm_replay.jsonl instead of calling the endpoint"
    )
    run.set_defaults(fn=_cmd_run)

    verify = sub.add_parser("verify", help="verify an audit pack has not been altered")
    verify.add_argument("pack", help="audit pack folder")
    verify.add_argument("--public-key", help="verify the pack is signed by this Ed25519 public key")
    verify.add_argument(
        "--require-signature", action="store_true", help="fail if the pack is not signed"
    )
    verify.set_defaults(fn=_cmd_verify)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 key pair for signing packs")
    keygen.add_argument("--out-dir", default=".", help="where to write the key pair")
    keygen.set_defaults(fn=_cmd_keygen)

    sign = sub.add_parser("sign", help="cryptographically sign an audit pack")
    sign.add_argument("pack", help="audit pack folder")
    sign.add_argument("--key", required=True, help="Ed25519 private key (PEM)")
    sign.set_defaults(fn=_cmd_sign)

    summary = sub.add_parser("summary", help="print a Markdown summary of an audit pack")
    summary.add_argument("pack", help="audit pack folder")
    summary.set_defaults(fn=_cmd_summary)

    diff = sub.add_parser("diff", help="compare two audit packs (e.g. before and after a fix)")
    diff.add_argument("old", help="earlier audit pack folder")
    diff.add_argument("new", help="later audit pack folder")
    diff.add_argument(
        "--fail-on-regression", action="store_true", help="exit 1 if any check got worse"
    )
    diff.set_defaults(fn=_cmd_diff)

    ping = sub.add_parser("ping", help="check that the LLM endpoint in a spec is reachable")
    ping.add_argument("spec")
    ping.set_defaults(fn=_cmd_ping)

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

    scan = sub.add_parser(
        "scan-trace",
        help="stream a large agent log and report misalignment signals (constant memory)",
    )
    scan.add_argument("source", help="agent log (JSON Lines streams; JSON array is read whole)")
    scan.add_argument("--format", default="native", choices=["native", "otel", "langchain"])
    scan.add_argument("-o", "--out", help="write signals as JSONL (default: stdout)")
    scan.add_argument(
        "--fail-on-signal",
        action="store_true",
        help="exit non-zero if any signal is found (for CI)",
    )
    scan.set_defaults(fn=_cmd_scan_trace)

    ingest = sub.add_parser(
        "ingest", help="convert a real agent log (OpenTelemetry/LangChain) to a Pramana trace"
    )
    ingest.add_argument("source", help="path to the agent log (JSON array or JSON Lines)")
    ingest.add_argument("--format", required=True, choices=["otel", "langchain", "native"])
    ingest.add_argument("-o", "--out", help="output .jsonl path (default: stdout)")
    ingest.set_defaults(fn=_cmd_ingest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
