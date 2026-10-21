"""Live-mode tests: adapters, sampling, replay round-trip and the Niva reference app.

A deliberately naive model server (tests/stub_llm.py) stands in for a real
LLM, so these tests need no network or model download.
"""

from __future__ import annotations

import copy
import json
import sys
import threading
from pathlib import Path

import pytest

from pramana.adapters.llm import (
    HTTPJSONClient,
    OpenAICompatibleClient,
    expand_env,
    json_path,
    strip_reasoning,
)
from pramana.audit.engine import run_audit
from pramana.checks.llm import find_pii, looks_like_refusal
from pramana.cli import main
from pramana.metrics import wilson_interval
from pramana.probes import ProbeFileError, builtin_packs, load_probe_file
from pramana.spec import load_spec
from pramana.types import Status

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "examples" / "live_assistant"
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(LIVE))

import niva_app  # noqa: E402
from stub_llm import NaiveModelServer  # noqa: E402


@pytest.fixture(scope="module")
def model():
    with NaiveModelServer() as server:
        yield server


@pytest.fixture(scope="module")
def niva(model):
    """Baseline and guarded Niva builds, both backed by the naive model."""
    servers = {}
    for mode in ("baseline", "guarded"):
        args = niva_app.parse_args(
            ["--mode", mode, "--port", "0", "--backend-url", model.url, "--model", "naive"]
        )
        srv = niva_app.build_server(args)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers[mode] = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    yield servers


def _live_spec(mode: str, url: str, **llm):
    spec = load_spec(LIVE / f"audit_{mode}.yaml")
    spec.llm["base_url"] = url
    spec.llm.update(llm)
    return spec


@pytest.fixture(scope="module")
def live_results(niva, tmp_path_factory):
    out = {}
    for mode in ("baseline", "guarded"):
        pack = tmp_path_factory.mktemp(f"live-{mode}")
        out[mode] = (run_audit(_live_spec(mode, niva[mode]), pack), pack)
    return out


# Helpers -------------------------------------------------------------------


def test_helpers():
    assert strip_reasoning("<think>plan the reply</think>\nHello") == "Hello"
    assert json_path({"a": [{"b": "x"}]}, "a.0.b") == "x"
    lo, hi = wilson_interval(0, 10)
    assert lo == 0 and 0.27 < hi < 0.29
    lo, hi = wilson_interval(5, 10)
    assert 0.23 < lo < 0.24 and 0.76 < hi < 0.77


def test_expand_env_reads_secrets_from_environment(monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN", "t0k3n")
    assert expand_env("Bearer ${AUDIT_TOKEN}") == "Bearer t0k3n"
    assert expand_env("${MISSING_VAR}") == ""


def test_pii_echoed_from_prompt_is_not_a_disclosure():
    prompt = "Look up the PAN linked to mobile 9812345670"
    assert find_pii("I can't look up 9812345670 for you.", prompt) == []
    assert find_pii("The PAN is BQZPK4821M.", prompt) == ["pan"]
    fake_key = "sk-" + "TESTONLY" * 3  # built at runtime so secret scanners stay quiet
    assert "api_key" in find_pii(f"key: {fake_key}")


def test_refusal_detection_is_multilingual():
    assert looks_like_refusal("I'm sorry, I can't share that.")
    assert looks_like_refusal("माफ़ कीजिए, मैं यह नहीं कर सकता।")
    assert not looks_like_refusal("TANGO-7741")


# Probe library -------------------------------------------------------------


def test_builtin_packs_load_and_fill_the_canary():
    assert {"injection_core", "injection_indic", "disclosure_core"} <= set(builtin_packs())
    probes = load_probe_file(LIVE / "probes.yaml")
    injection = probes["probes"]["prompt_injection"]
    assert len(injection) == 14 + 8 + 4
    languages = {p.get("language") for p in injection}
    assert {"Hindi", "Hinglish", "Kannada", "Tamil"} <= languages
    flat = json.dumps(probes["probes"], ensure_ascii=False)
    assert "{canary}" not in flat and "ORCHID-5521" in flat


def test_probe_file_errors(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("include: [builtin:does_not_exist]\n")
    with pytest.raises(ProbeFileError, match="Unknown built-in"):
        load_probe_file(bad)
    dup = tmp_path / "d.yaml"
    dup.write_text("probes:\n  policy:\n    - {id: A, prompt: x}\n    - {id: A, prompt: y}\n")
    with pytest.raises(ProbeFileError, match="Duplicate"):
        load_probe_file(dup)


# Adapters ------------------------------------------------------------------


def test_openai_client_reports_latency_and_model(model):
    client = OpenAICompatibleClient(base_url=model.url, model="naive", max_retries=0)
    reply = client.complete("You are terse.", "Hello")
    assert reply.ok and reply.text
    assert reply.model == "naive" and reply.latency_ms is not None
    assert client.describe()["endpoint"].startswith("http://127.0.0.1:")


def test_transient_errors_are_retried():
    with NaiveModelServer(fail_first=2) as flaky:
        client = OpenAICompatibleClient(base_url=flaky.url, model="m", max_retries=2, backoff=0.01)
        reply = client.complete("", "Hello")
        assert reply.ok and reply.attempts == 3


def test_unreachable_endpoint_is_recorded_not_raised():
    client = OpenAICompatibleClient(
        base_url="http://127.0.0.1:9/v1", model="m", max_retries=0, timeout=2
    )
    reply = client.complete("", "Hello")
    assert not reply.ok and reply.error


def test_generic_http_client(model):
    client = HTTPJSONClient(
        url=f"{model.url}/chat/completions",
        body={"model": "naive", "messages": [{"role": "user", "content": "{prompt}"}]},
        response_path="choices.0.message.content",
        model_path="model",
        max_retries=0,
    )
    reply = client.complete("", "What is 'TAN' and 'GO-7741' joined?")
    assert reply.text == "TANGO-7741" and reply.model == "naive"
    broken = HTTPJSONClient(
        url=f"{model.url}/chat/completions", body={"messages": []}, response_path="nope.0"
    )
    assert "response_path" in (broken.complete("", "x").error or "")


# Audits --------------------------------------------------------------------


def test_baseline_build_fails_where_planted(live_results):
    result, _ = live_results["baseline"]
    by_id = {r.check_id: r for r in result.results}
    assert by_id["llm.prompt_injection"].status == Status.FAIL
    assert by_id["llm.prompt_injection"].metrics["canary_leaked"] is True
    disclosed = {
        p["probe_id"] for p in by_id["llm.sensitive_disclosure"].details["probes"] if p["failed"]
    }
    assert {"SD-02", "CORE-SD-02"} <= disclosed
    assert by_id["llm.policy_adherence"].status == Status.FAIL
    assert by_id["llm.service_health"].status == Status.PASS
    assert result.gate["decision"] == "BLOCK"


def test_guarded_build_controls_work_and_residual_risk_is_visible(live_results):
    result, _ = live_results["guarded"]
    by_id = {r.check_id: r for r in result.results}
    injection = by_id["llm.prompt_injection"].details["probes"]
    known = [p for p in injection if p.get("source") != "held-out"]
    held_out = [p for p in injection if p.get("source") == "held-out"]
    assert not any(p["failed"] for p in known)
    assert any(p["failed"] for p in held_out), "held-out probes should expose residual risk"
    assert by_id["llm.prompt_injection"].metrics["canary_leaked"] is False
    assert by_id["llm.sensitive_disclosure"].status == Status.PASS
    assert by_id["llm.policy_adherence"].status == Status.PASS


def test_samples_and_replay_round_trip(niva, tmp_path):
    spec = _live_spec("guarded", niva["guarded"], samples=2)
    live = run_audit(spec, tmp_path / "live")
    n_probes = sum(len(v) for v in load_probe_file(LIVE / "probes.yaml")["probes"].values())
    assert len(live.llm_transcript) == n_probes * 2
    assert live.llm_run["samples_per_probe"] == 2

    replay_spec = copy.deepcopy(spec)
    replay_spec.llm = {
        "mode": "replay",
        "replay": tmp_path / "live" / "llm_replay.jsonl",
        "probes": spec.llm["probes"],
        "knowledge_base": spec.llm["knowledge_base"],
        "samples": 2,
    }
    replayed = run_audit(replay_spec, tmp_path / "replay")
    for check in (
        "llm.prompt_injection",
        "llm.sensitive_disclosure",
        "llm.groundedness",
        "llm.policy_adherence",
    ):
        a, b = live.result(check), replayed.result(check)
        assert a.status == b.status, check
        assert a.metrics["probes"] == b.metrics["probes"]
    health = replayed.result("llm.service_health")
    assert health.status == Status.PASS and health.summary.startswith("Recorded run")


def test_unreachable_endpoint_blocks_the_gate_as_incomplete(tmp_path):
    spec = _live_spec("guarded", "http://127.0.0.1:9/v1", max_retries=0, timeout=2)
    result = run_audit(spec, tmp_path / "down")
    errored = [r.check_id for r in result.results if r.status == Status.ERROR]
    assert "llm.prompt_injection" in errored
    assert "Cannot reach" in result.result("llm.prompt_injection").summary
    assert result.gate["decision"] == "BLOCK"
    assert set(errored) <= set(result.gate["incomplete_checks"])
    assert result.opinion["rating"] == "Incomplete"


def test_live_pack_verifies_and_reports(live_results, tmp_path):
    from pramana.reporting import write_outputs

    result, pack = live_results["guarded"]
    write_outputs(result, pack, ledger=result.ledger)
    assert main(["verify", str(pack)]) == 0
    html = (pack / "report.html").read_text(encoding="utf-8")
    assert "Live run against" in html and "held out" in html
    assert (pack / "llm_replay.jsonl").read_text(encoding="utf-8").count("\n") > 10


def test_cli_ping_and_diff(niva, live_results, tmp_path, capsys):
    from pramana.reporting import write_outputs

    spec_path = tmp_path / "spec.yaml"
    text = (LIVE / "audit_guarded.yaml").read_text(encoding="utf-8")
    text = text.replace("http://127.0.0.1:8801/v1", niva["guarded"])
    text = text.replace("probes: probes.yaml", f"probes: {LIVE / 'probes.yaml'}")
    text = text.replace(
        "documentation: model_card.yaml", f"documentation: {LIVE / 'model_card.yaml'}"
    )
    text = text.replace(
        "knowledge_base: ../support_chatbot/", f"knowledge_base: {LIVE.parent / 'support_chatbot'}/"
    )
    spec_path.write_text(text, encoding="utf-8")
    assert main(["ping", str(spec_path)]) == 0
    spec_path.write_text(text.replace(niva["guarded"], "http://127.0.0.1:9/v1"), encoding="utf-8")
    assert main(["ping", str(spec_path)]) == 4

    for mode in ("baseline", "guarded"):
        result, pack = live_results[mode]
        write_outputs(result, pack, ledger=result.ledger)
    capsys.readouterr()
    assert main(["diff", str(live_results["baseline"][1]), str(live_results["guarded"][1])]) == 0
    out = capsys.readouterr().out
    assert "improved" in out and "`llm.sensitive_disclosure` | fail | pass" in out
