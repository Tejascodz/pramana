"""HTTP tool server: test a customer's own agent, framework and all, in the sandbox.

Point the agent's tool functions at this server instead of the real systems, run it
on each scenario's task, then audit the trace it records:

    pramana sandbox serve --out sandbox_trace.jsonl          # terminal 1
    # your agent: POST /sessions, then POST /sessions/<id>/tools/<tool> for each call
    pramana run audit.yaml   # agent.trace: sandbox_trace.jsonl, agent.scenarios: builtin:core

Endpoints (JSON in, JSON out):

    GET  /scenarios                              ids, titles and tasks
    GET  /tools                                  tool definitions (OpenAI format)
    POST /sessions            {"scenario": id}   -> {"session_id", "task", "tools"}
    POST /sessions/<id>/tools/<name>   {args}    -> {"result": "..."}
    POST /sessions/<id>/output {"content", "reasoning"}   record the agent's reply

The server listens on 127.0.0.1 only, refuses requests a web page could send (any
Origin header, non-JSON bodies, foreign Host headers) and caps bodies at 1 MB. The
trace is rewritten after every call, so stopping the server never loses a session.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pramana.sandbox import APPROVERS, Session, load_scenarios, tool_schemas

MAX_BODY = 1024 * 1024
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class SandboxServer:
    def __init__(self, scenarios_source: str, out: Path, approver: str = "deny"):
        self.scenarios = {s["id"]: s for s in load_scenarios(scenarios_source)}
        self.out = Path(out)
        self.approver = APPROVERS[approver]
        self.sessions: dict[str, Session] = {}
        self.events: list[dict[str, Any]] = []  # every session, in the order things happened
        self.runs: dict[str, int] = {}
        self.prev_hash: str | None = None
        self.lock = threading.Lock()

    def start_session(self, scenario_id: str) -> dict[str, Any]:
        scenario = self.scenarios.get(scenario_id)
        if scenario is None:
            raise KeyError(f"unknown scenario '{scenario_id}'")
        n = self.runs[scenario_id] = self.runs.get(scenario_id, 0) + 1
        session = Session(
            scenario, f"{scenario_id}~{n}", approver=self.approver, prev_hash=self.prev_hash
        )
        self.sessions[session.session_id] = session
        self._save(session, 0)
        return {"session_id": session.session_id, "task": scenario["task"], "tools": tool_schemas()}

    def _save(self, session: Session, before: int) -> None:
        """Append the session's new events to the one chain and rewrite the trace."""
        self.events.extend(session.events[before:])
        self.prev_hash = session.prev_hash
        text = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in self.events)
        self.out.write_text(text, encoding="utf-8")

    def call(self, session_id: str, tool: str, args: dict[str, Any]) -> str:
        session = self.sessions[session_id]
        session.prev_hash = self.prev_hash  # sessions may interleave; keep one chain
        before = len(session.events)
        result = session.call_tool(tool, args)
        self._save(session, before)
        return result

    def output(self, session_id: str, content: str, reasoning: str) -> None:
        session = self.sessions[session_id]
        session.prev_hash = self.prev_hash
        before = len(session.events)
        session.model_output(content, reasoning=reasoning)
        self._save(session, before)


def make_handler(app: SandboxServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            return

        def _send(self, code: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _refused(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            if self.headers.get("Origin") or host not in LOCAL_HOSTS:
                self._send(403, {"error": "forbidden"})
                return True
            return False

        def _body(self) -> dict[str, Any] | None:
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            length = int(self.headers.get("Content-Length") or 0)
            if ctype != "application/json" or not 0 < length <= MAX_BODY:
                return None
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None
            return data if isinstance(data, dict) else None

        def do_GET(self) -> None:  # noqa: N802
            if self._refused():
                return
            if self.path == "/scenarios":
                self._send(
                    200,
                    [
                        {"id": s["id"], "title": s.get("title", ""), "task": s["task"]}
                        for s in app.scenarios.values()
                    ],
                )
            elif self.path == "/tools":
                self._send(200, tool_schemas())
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self._refused():
                return
            body = self._body()
            if body is None:
                self._send(400, {"error": "send a JSON object with Content-Type application/json"})
                return
            parts = [p for p in self.path.split("/") if p]
            with app.lock:
                try:
                    if parts == ["sessions"]:
                        self._send(200, app.start_session(str(body.get("scenario", ""))))
                    elif len(parts) == 4 and parts[0] == "sessions" and parts[2] == "tools":
                        self._send(200, {"result": app.call(parts[1], parts[3], body)})
                    elif len(parts) == 3 and parts[0] == "sessions" and parts[2] == "output":
                        app.output(
                            parts[1], str(body.get("content", "")), str(body.get("reasoning", ""))
                        )
                        self._send(200, {"ok": True})
                    else:
                        self._send(404, {"error": "not found"})
                except KeyError as exc:
                    self._send(404, {"error": str(exc).strip("'\"")})

    return Handler


def serve(app: SandboxServer, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
