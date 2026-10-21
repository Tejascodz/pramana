# Security

Pramana is an audit tool that you run on your own computer or in CI. This page
sets out what it listens on, what it sends, what it stores, and what it trusts.

## What listens on the network

| Component | Listens on | Notes |
|---|---|---|
| `pramana` CLI | Nothing | A client only. It makes requests to the endpoint named in the audit spec and to nothing else |
| Niva reference app (`examples/live_assistant`) | `127.0.0.1` | Refuses any other address unless started with `--allow-remote`, and refuses requests a web page could make (see below) |
| Dashboard (`dashboard/app.py`) | `127.0.0.1:8501` | Set in `.streamlit/config.toml`; usage statistics are off |
| Test stubs | `127.0.0.1`, random port | Only while the tests run |
| Ollama (separate software) | `127.0.0.1:11434` by default | Keep *Expose Ollama to the network* off, do not set `OLLAMA_HOST=0.0.0.0`, and leave `OLLAMA_ORIGINS` unset |

To confirm on macOS or Linux while the services are running:

```bash
lsof -nP -iTCP -sTCP:LISTEN | grep -E ':(8501|8800|8801|11434) '
```

Every line should show `127.0.0.1` or `[::1]`. A `*` or `0.0.0.0` means the
port is open to your network.

### Web pages in your browser

A loopback server cannot be reached from your network, but a web page open in
your browser can still try to send it requests. Niva refuses them:

- **DNS rebinding.** A page whose domain is made to resolve to `127.0.0.1` sends
  its own domain in the `Host` header; Niva only answers `localhost`,
  `127.0.0.1` and `[::1]`.
- **Cross-site requests.** Browsers add an `Origin` header and cannot send a JSON
  body to another site without a permission check that Niva never grants. Niva
  refuses any request with an `Origin` header and any body that is not JSON.

Ollama applies its own origin and host checks; keep them by leaving
`OLLAMA_ORIGINS` unset.

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
  are refused, and so are credentials written into a URL.
- **Redirects are refused.** Python would otherwise resend every header, keys
  included, to wherever a redirect points.
- **Responses are capped** at 10 MB, and Niva caps requests at 1 MB, so a
  misbehaving server cannot exhaust memory.
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
- **Audit packs from someone else are untrusted data.** `pramana verify` only
  reads files inside the pack, and the dashboard shows a pack's text as plain
  text, so it cannot load images or links from it.

## CI

- Workflows run with a read-only token (`permissions: contents: read`), use no
  repository secrets, and do not run on `pull_request_target`.
- Third-party actions are pinned to full commit SHAs, and Dependabot proposes
  updates to them.
- `actions/checkout` does not keep the token in the working copy
  (`persist-credentials: false`), so it cannot end up in an uploaded artifact.
- The composite action passes its inputs to the shell as environment
  variables, never as script text.

## Dependencies

The core package has no known vulnerable dependencies (checked with
`pip-audit`) and sets minimum versions above known advisories (Jinja2 3.1.6,
scikit-learn 1.5). The optional dashboard depends on Streamlit, which currently
limits Pillow to the 12.x series; the advisories fixed in Pillow 13 concern
opening or saving untrusted image and PDF files, which the dashboard never does.

## Reporting a problem

Please report security issues privately through **Report a vulnerability** on the
repository's *Security* tab rather than in a public issue.

## Checking it yourself

```bash
pip install bandit pip-audit
bandit -r src dashboard examples        # static analysis
pip-audit                               # known-vulnerable dependencies
gitleaks git .                          # secrets in the full git history
pytest tests/test_security.py           # the properties on this page
```
