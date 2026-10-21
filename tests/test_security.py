"""Safety properties of the tool itself: what it listens on, what it sends, and where."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from pramana.adapters.llm import HTTPJSONClient, OpenAICompatibleClient, _fill

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "live_assistant"))

import niva_app  # noqa: E402


def test_environment_variables_are_not_expanded_in_urls_or_bodies(monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "do-not-send")
    body = _fill({"q": "{prompt}", "note": "${SECRET_TOKEN}"}, {"prompt": "hi"})
    assert body == {"q": "hi", "note": "${SECRET_TOKEN}"}
    client = HTTPJSONClient(
        url="http://127.0.0.1:9/${SECRET_TOKEN}", body={"q": "{prompt}"}, response_path="a"
    )
    assert "do-not-send" not in client.url
    openai = OpenAICompatibleClient(base_url="http://127.0.0.1:9/${SECRET_TOKEN}", model="m")
    assert "do-not-send" not in openai.base_url


def test_header_secrets_still_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN", "t0k3n")
    client = OpenAICompatibleClient(
        base_url="https://api.example.com/v1",
        model="m",
        headers={"Authorization": "Bearer ${AUDIT_TOKEN}"},
    )
    assert client.headers["Authorization"] == "Bearer t0k3n"


def test_credentials_are_never_sent_over_plain_http_to_another_host(monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN", "t0k3n")
    with pytest.raises(ValueError, match="plain HTTP"):
        OpenAICompatibleClient(
            base_url="http://192.168.1.20:8000/v1", model="m", api_key_env="AUDIT_TOKEN"
        )
    with pytest.raises(ValueError, match="plain HTTP"):
        HTTPJSONClient(
            url="http://app.example.com/chat",
            body={"q": "{prompt}"},
            response_path="a",
            headers={"X-Api-Key": "${AUDIT_TOKEN}"},
        )
    # Allowed: https anywhere, or plain HTTP to this computer.
    OpenAICompatibleClient(
        base_url="https://api.example.com/v1", model="m", api_key_env="AUDIT_TOKEN"
    )
    OpenAICompatibleClient(
        base_url="http://127.0.0.1:8800/v1", model="m", api_key_env="AUDIT_TOKEN"
    )
    # No credentials: plain HTTP is fine (a lab model on another machine, say).
    OpenAICompatibleClient(base_url="http://192.168.1.20:8000/v1", model="m")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "127.0.0.1:8800"])
def test_only_http_endpoints_are_accepted(url):
    with pytest.raises(ValueError, match="http"):
        OpenAICompatibleClient(base_url=url, model="m")
    with pytest.raises(ValueError, match="http"):
        HTTPJSONClient(url=url, body={"q": "{prompt}"}, response_path="a")


def test_niva_listens_on_this_computer_only_by_default():
    args = niva_app.parse_args(["--port", "0"])
    assert args.host == "127.0.0.1"
    with pytest.raises(SystemExit, match="Refusing to listen on 0.0.0.0"):
        niva_app.build_server(niva_app.parse_args(["--host", "0.0.0.0", "--port", "0"]))
    server = niva_app.build_server(args)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_dashboard_is_local_only_and_sends_no_usage_statistics():
    tomllib = pytest.importorskip("tomllib")  # Python 3.11+
    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert config["server"]["address"] == "127.0.0.1"
    assert config["browser"]["gatherUsageStats"] is False


def test_workflows_have_read_only_permissions_and_no_secrets():
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(text)
        assert workflow["permissions"] == {"contents": "read"}, path.name
        assert "secrets." not in text and "pull_request_target" not in text, path.name


def test_model_output_cannot_run_script_in_the_report(tmp_path):
    """A hostile answer is shown as text in report.html, never executed."""
    import copy
    import json

    from pramana.audit.engine import run_audit
    from pramana.probes import load_probe_file
    from pramana.reporting import write_outputs
    from pramana.spec import load_spec

    live = ROOT / "examples" / "live_assistant"
    payload = "<script>alert('x')</script><img src=x onerror=alert(1)>"
    probes = load_probe_file(live / "probes.yaml")["probes"]
    replay = tmp_path / "hostile.jsonl"
    with replay.open("w", encoding="utf-8") as fh:
        for group in probes.values():
            for probe in group:
                fh.write(json.dumps({"prompt": probe["prompt"], "responses": [payload]}) + "\n")

    spec = copy.deepcopy(load_spec(live / "audit_guarded.yaml"))
    spec.llm = {
        "mode": "replay",
        "replay": replay,
        "probes": spec.llm["probes"],
        "knowledge_base": spec.llm["knowledge_base"],
    }
    result = run_audit(spec, tmp_path / "pack")
    write_outputs(result, tmp_path / "pack", ledger=result.ledger)
    html = (tmp_path / "pack" / "report.html").read_text(encoding="utf-8")
    assert "<script" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html
