"""Regression tests: replay recordings and LLM endpoint settings are validated.

A malformed recording used to crash with an AttributeError or KeyError, and a
recording with fewer latencies than responses was loaded in part, silently dropping
samples. Endpoint settings such as a negative timeout or a fractional retry count were
accepted, and decoding errors were reported as a missing response_path. Every test
here failed before 0.8.0, except the ones named as controls.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pramana.adapters.llm import HTTPJSONClient, OpenAICompatibleClient, ReplayClient, build_client


def replay_file(tmp_path, lines: list, suffix=".jsonl"):
    path = tmp_path / f"replay{suffix}"
    if suffix == ".json":
        path.write_text(json.dumps(lines))
    else:
        path.write_text("\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines))
    return path


# ---------------------------------------------------------------------------------------
# Replay recordings
# ---------------------------------------------------------------------------------------


def test_control_a_good_recording_loads(tmp_path):
    client = ReplayClient(
        replay_file(tmp_path, [{"prompt": "hi", "responses": ["a", "b"], "latencies_ms": [1, 2]}])
    )
    assert [client.complete("", "hi", sample=i).text for i in range(2)] == ["a", "b"]


def test_fewer_latencies_than_responses_is_refused_not_truncated(tmp_path):
    path = replay_file(
        tmp_path, [{"prompt": "hi", "responses": ["a", "b", "c"], "latencies_ms": [5]}]
    )
    with pytest.raises(ValueError, match="one value per response"):
        ReplayClient(path)


@pytest.mark.parametrize(
    "line,match",
    [
        ([1, 2], "expected an object"),
        ("null", "expected an object"),
        ('"text"', "expected an object"),
        ("{bad json", "not valid JSON"),
        ({"prompt": "hi", "responses": []}, "non-empty list"),
        ({"prompt": "hi"}, "needs 'response'"),
        ({"response": "x"}, "prompt"),
        ({"prompt": 5, "response": "x"}, "prompt"),
        ({"prompt": "hi", "response": 5}, "must be text"),
        ({"prompt": "hi", "responses": "abc"}, "non-empty list"),
        ({"conversation": "hi", "response": "x"}, "conversation"),
        ({"prompt": "hi", "response": "x", "latencies_ms": [-1]}, "latency"),
        ({"prompt": "hi", "response": "x", "latencies_ms": "fast"}, "one value per response"),
    ],
)
def test_a_malformed_jsonl_record_is_refused_with_its_line(tmp_path, line, match):
    good = {"prompt": "ok", "response": "fine"}
    with pytest.raises(ValueError, match=match) as info:
        ReplayClient(replay_file(tmp_path, [good, line]))
    assert ":2" in str(info.value)  # names the line


@pytest.mark.parametrize("entry", ["text", None, 7, [1]])
def test_a_transcript_entry_that_is_not_an_object_is_refused(tmp_path, entry):
    good = {"prompt": "ok", "response": "fine", "sample": 0}
    with pytest.raises(ValueError, match="entry 2"):
        ReplayClient(replay_file(tmp_path, [good, entry], suffix=".json"))


def test_a_transcript_with_wrong_types_is_refused(tmp_path):
    with pytest.raises(ValueError, match="sample"):
        ReplayClient(replay_file(tmp_path, [{"prompt": "a", "sample": "0"}], suffix=".json"))


def test_a_recording_that_is_not_utf8_is_refused_cleanly(tmp_path):
    path = tmp_path / "replay.jsonl"
    path.write_bytes(b'{"prompt": "\xff", "response": "x"}')
    with pytest.raises(ValueError, match="UTF-8"):
        ReplayClient(path)


# ---------------------------------------------------------------------------------------
# Endpoint settings
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "setting",
    [
        {"timeout": -1},
        {"timeout": 0},
        {"timeout": float("nan")},
        {"max_retries": -1},
        {"max_retries": 1.5},
        {"max_retries": True},
        {"max_retries": "3"},
        {"backoff": -0.5},
        {"backoff": float("inf")},
    ],
)
def test_invalid_endpoint_settings_are_refused_when_the_client_is_built(setting):
    with pytest.raises(ValueError):
        OpenAICompatibleClient(base_url="http://127.0.0.1:9/v1", model="m", **setting)
    with pytest.raises(ValueError):
        build_client(
            {
                "mode": "openai_compatible",
                "base_url": "http://127.0.0.1:9/v1",
                "model": "m",
                **setting,
            }
        )


@pytest.mark.parametrize(
    "setting", [{"samples": 0}, {"samples": 2.5}, {"concurrency": -2}, {"temperature": "hot"}]
)
def test_invalid_llm_settings_are_refused_when_the_spec_loads(tmp_path, setting):
    import yaml

    from pramana.spec import SpecError, load_spec

    spec = {
        "system": {"name": "S", "version": "1", "type": "llm_application", "owner": "o"},
        "use_case": {"domain": "other"},
        "llm": {"mode": "replay", "replay": "r.jsonl", **setting},
    }
    (tmp_path / "audit.yaml").write_text(yaml.safe_dump(spec))
    with pytest.raises(SpecError, match=next(iter(setting))):
        load_spec(tmp_path / "audit.yaml")


@pytest.mark.parametrize("setting", [{"max_retries": 0}, {"backoff": 0}])
def test_control_zero_retries_and_zero_backoff_are_allowed(setting):
    OpenAICompatibleClient(base_url="http://127.0.0.1:9/v1", model="m", **setting)


# ---------------------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------------------


class _Server:
    def __init__(self, body: bytes):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/chat"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.mark.parametrize(
    "body,expected,not_expected",
    [
        (b"\xff\xfe\xfd", "not valid UTF-8", "response_path"),
        (b"not json", "did not return JSON", "response_path"),
        (b'{"other": "x"}', "response_path 'answer' not found", None),
    ],
)
def test_http_errors_name_their_real_cause(body, expected, not_expected):
    server = _Server(body)
    try:
        client = HTTPJSONClient(
            url=server.url, body={"q": "{prompt}"}, response_path="answer", max_retries=0
        )
        result = client.complete("", "hello")
    finally:
        server.close()
    assert result.error and expected in result.error
    if not_expected:
        assert not_expected not in result.error


def test_control_a_good_http_reply_is_read():
    server = _Server(b'{"answer": "hello back"}')
    try:
        result = HTTPJSONClient(
            url=server.url, body={"q": "{prompt}"}, response_path="answer"
        ).complete("", "hello")
    finally:
        server.close()
    assert result.text == "hello back" and not result.error


@pytest.mark.parametrize("value", ["0", "-3", "2.5", "many"])
def test_the_samples_flag_is_validated(value, capsys):
    from conftest import EXAMPLES

    from pramana.cli import main

    with pytest.raises(SystemExit) as info:
        main(["run", str(EXAMPLES / "support_chatbot" / "audit.yaml"), "--samples", value])
    assert info.value.code == 2
    assert "--samples" in capsys.readouterr().err
