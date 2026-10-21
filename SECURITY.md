# Security

Pramana is an audit tool that you run on your own computer or in CI. This page
sets out what it listens on, what it sends, what it stores, and what it trusts.

## What listens on the network

| Component | Listens on | Notes |
|---|---|---|
| `pramana` CLI | Nothing | A client only. It makes requests to the endpoint named in the audit spec and to nothing else |
| Niva reference app (`examples/live_assistant`) | `127.0.0.1` | Refuses any other address unless started with `--allow-remote` |
| Dashboard (`dashboard/app.py`) | `127.0.0.1:8501` | Set in `.streamlit/config.toml`; usage statistics are off |
| Test stubs | `127.0.0.1`, random port | Only while the tests run |
| Ollama (separate software) | `127.0.0.1:11434` by default | Keep *Expose Ollama to the network* off, and do not set `OLLAMA_HOST=0.0.0.0` |

To confirm on macOS or Linux while the services are running:

```bash
lsof -nP -iTCP -sTCP:LISTEN | grep -E ':(8501|8800|8801|11434) '
```

Every line should show `127.0.0.1` or `[::1]`. A `*` or `0.0.0.0` means the
port is open to your network.

## What it sends

- **No telemetry.** No analytics, crash reports or update checks. The only network
  traffic is to the endpoint in your spec.
- **Credentials come from the environment, in headers only.** `${VAR}` is expanded
  in header values and `api_key_env` names an environment variable; neither is
  ever written to an audit pack. URLs and request bodies are sent exactly as
  written, so environment values cannot end up in them.
- **Credentials are only sent over https**, or to an endpoint on this computer.
  A spec that would send a key over plain HTTP to another host is refused.
- **Only `http` and `https` endpoints are accepted.** `file://` and other schemes
  are refused.
- **Evidence names the endpoint by scheme, host and port only.** No paths, query
  strings or tokens.

## What it stores

- **Audit packs** (`packs/`, ignored by git) hold the probes that were sent and the
  answers that came back, so a reviewer can check every verdict. Treat a pack
  from a real system like that system's logs, and do not commit one.
- **The recordings in this repository** (`examples/live_assistant/recorded`)
  contain only Pramana's own synthetic probes and the answers of the fictional
  Niva app. Every customer record is invented.
- **Pramana never reads model files, chat history or any other data held by
  Ollama or another model server.** It sees only the answers to its own
  requests.

## What it trusts

- **Audit specs and probe files are configuration.** A spec chooses the endpoint
  and which environment variable is sent as a credential. Only run specs you
  wrote or reviewed, as you would a CI workflow. Specs are parsed with
  `yaml.safe_load`, which does not create Python objects.
- **Model files are code.** `artifacts.model` is loaded with joblib, which uses
  pickle, and loading a pickle can run code. Only audit model files that came
  through a trusted, access-controlled channel, or audit from predictions
  (`score_column`) instead.
- **Model output is untrusted text.** The HTML report escapes everything it
  shows, so an answer containing HTML or script is displayed, never run.

## CI

The workflows run with a read-only token (`permissions: contents: read`), use no
repository secrets, and do not run on `pull_request_target`.

## Reporting a problem

Please report security issues privately through **Report a vulnerability** on the
repository's *Security* tab rather than in a public issue.
