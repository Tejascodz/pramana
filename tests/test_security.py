"""Safety properties of the tool itself: what it listens on, what it sends, and where."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from pramana.adapters.llm import HTTPJSONClient, OpenAICompatibleClient, _fill

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "live_assistant"))
sys.path.insert(0, str(Path(__file__).parent))

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


# Network behaviour ----------------------------------------------------------


class _Recorder:
    """Two local servers: one redirects every request to the other, which records headers."""

    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.received: list[dict] = []
        recorder = self

        class Target(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                recorder.received.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"choices": [{"message": {"content": "hi"}}]}')

            def log_message(self, *args):
                return

        self.target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        target_url = f"http://127.0.0.1:{self.target.server_address[1]}/v1/chat/completions"

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                self.send_response(307)
                self.send_header("Location", target_url)
                self.end_headers()

            def log_message(self, *args):
                return

        self.redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        for server in (self.target, self.redirect):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.redirect.server_address[1]}/v1"

    def close(self):
        for server in (self.target, self.redirect):
            server.shutdown()
            server.server_close()


def test_redirects_are_refused_so_keys_never_reach_another_server(monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN", "t0k3n")
    servers = _Recorder()
    try:
        client = OpenAICompatibleClient(
            base_url=servers.url, model="m", api_key_env="AUDIT_TOKEN", max_retries=0
        )
        reply = client.complete("", "Hello")
        assert not reply.ok and "redirect" in reply.error
        assert servers.received == []
    finally:
        servers.close()


def test_oversized_responses_are_refused(monkeypatch):
    from stub_llm import NaiveModelServer

    import pramana.adapters.llm as llm

    monkeypatch.setattr(llm, "MAX_RESPONSE_BYTES", 10)
    with NaiveModelServer() as model:
        reply = OpenAICompatibleClient(base_url=model.url, model="m", max_retries=0).complete(
            "", "Hello"
        )
    assert not reply.ok and "larger than" in reply.error


def test_credentials_in_urls_are_refused():
    with pytest.raises(ValueError, match="not in the URL"):
        OpenAICompatibleClient(base_url="https://user:secret@api.example.com/v1", model="m")


# Niva: what a web page in the browser could try ---------------------------------


@pytest.fixture(scope="module")
def niva_url():
    import threading

    from stub_llm import NaiveModelServer

    with NaiveModelServer() as model:
        args = niva_app.parse_args(["--port", "0", "--backend-url", model.url, "--model", "m"])
        server = niva_app.build_server(args)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        yield "127.0.0.1", server.server_address[1]
        server.shutdown()
        server.server_close()


def _post(addr, body: bytes, headers: dict) -> tuple[int, dict]:
    import http.client
    import json

    conn = http.client.HTTPConnection(*addr, timeout=10)
    conn.putrequest("POST", "/v1/chat/completions", skip_host=True)
    headers = {"Content-Length": str(len(body)), **headers}
    for key, value in headers.items():
        conn.putheader(key, value)
    conn.endheaders(body)
    response = conn.getresponse()
    payload = json.loads(response.read() or b"{}")
    conn.close()
    return response.status, payload


CHAT = b'{"messages": [{"role": "user", "content": "What is the interest rate?"}]}'


def test_niva_answers_local_api_clients(niva_url):
    host = f"127.0.0.1:{niva_url[1]}"
    status, payload = _post(niva_url, CHAT, {"Host": host, "Content-Type": "application/json"})
    assert status == 200 and payload["choices"][0]["message"]["content"]


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"Host": "attacker.example:8800", "Content-Type": "application/json"}, 403),  # rebinding
        (
            {
                "Host": "127.0.0.1",
                "Origin": "https://attacker.example",
                "Content-Type": "application/json",
            },
            403,
        ),  # cross-site request from a browser
        ({"Host": "127.0.0.1", "Content-Type": "text/plain"}, 415),  # form-style post
    ],
)
def test_niva_refuses_requests_a_web_page_could_make(niva_url, headers, status):
    assert _post(niva_url, CHAT, headers)[0] == status


def test_niva_rejects_bad_bodies_without_leaking_details(niva_url):
    headers = {"Host": "127.0.0.1", "Content-Type": "application/json"}
    status, payload = _post(niva_url, b"{not json", headers)
    assert status == 400 and "Traceback" not in json_dumps(payload)
    too_big = {**headers, "Content-Length": str(niva_app.MAX_REQUEST_BYTES + 1)}
    assert _post(niva_url, b"", too_big)[0] == 413


def json_dumps(value) -> str:
    import json

    return json.dumps(value)


def test_niva_backend_must_be_http():
    with pytest.raises(SystemExit, match="http"):
        niva_app.Niva(niva_app.parse_args(["--backend-url", "file:///etc"]))


# Evidence packs from someone else -----------------------------------------------


def test_verify_never_reads_outside_the_pack(tmp_path):
    import json

    from pramana.audit.ledger import _entry_hash, verify_pack

    (tmp_path / "outside.txt").write_text("not evidence", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    entry = {"seq": 1, "prev_hash": None, "kind": "evidence", "name": "x", "path": "../outside.txt"}
    entry["sha256"] = "0" * 64
    entry["entry_hash"] = _entry_hash(entry)
    (pack / "ledger.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    ok, problems = verify_pack(pack)
    assert not ok and "outside the pack" in problems[0]


def test_dashboard_shows_pack_text_as_text():
    pytest.importorskip("streamlit")
    sys.path.insert(0, str(ROOT / "dashboard"))
    import app

    shown = app.plain("![x](http://attacker.example/p.png) **bold**")
    assert "![" not in shown and "](" not in shown and "**" not in shown
