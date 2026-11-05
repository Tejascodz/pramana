# Security

Pramana is an audit tool that you run on your own computer or in CI. This page
sets out what it listens on, what it sends, what it stores, and what it trusts.

## What listens on the network

| Component | Listens on | Notes |
|---|---|---|
| `pramana` CLI | Nothing | A client only. It makes requests to the endpoint named in the audit spec and to nothing else |
| Niva reference app (`examples/live_assistant`) | `127.0.0.1` | Refuses any other address unless started with `--allow-remote`, and refuses requests a web page could make (see below) |
| Dashboard (`dashboard/app.py`) | `127.0.0.1:8501` | Set in `.streamlit/config.toml`; usage statistics are off |
| Sandbox tool server (`pramana sandbox serve`) | `127.0.0.1:8900` | Loopback only, no option to bind elsewhere; refuses any `Origin` header, foreign `Host` headers and non-JSON bodies; bodies capped at 1 MB |
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
- **Signing keys live outside the repository.** `pramana keygen` writes the
  Ed25519 key pair to `~/.pramana/keys` (private key readable by the owner
  only), refuses to write inside a git working tree unless told to, and never
  overwrites an existing key without `--force`. In CI, keep the private key in
  a secret store and pass it as `PRAMANA_SIGNING_KEY_PEM`. `.gitignore`
  excludes `*.key`, `*.pem` and `pramana_ed25519.*`. Only the public key
  should ever be shared.
- **If a private key is exposed, treat it as compromised.** Generate a new key,
  re-sign the packs you still rely on, publish the new public key, and remove
  the old key from version-control history (for example with
  `git filter-repo`). Removing it from the latest commit alone is not enough.

## What it trusts

- **Audit specs and probe files are configuration.** A spec chooses the endpoint
  and which environment variable is sent as a credential. Only run specs you
  wrote or reviewed, as you would a CI workflow. Specs are parsed with
  `yaml.safe_load`, which does not create Python objects.
- **Pickled model files are code, so Pramana refuses them by default.** A
  `.joblib` or `.pkl` model can run code the moment it is loaded. Pramana loads
  one only when its SHA-256 is pinned under `artifacts_sha256.model` (then a
  swapped file is refused before it is unpickled) or when you vouch for it with
  `trust_pickled_model: true` in the spec or `pramana run --trust-model`. Safer
  options: save the model as `.skops` (`pip install "pramana-audit[skops]"`),
  which loads without unpickling and only accepts scikit-learn, NumPy and SciPy
  types, or audit from predictions (`score_column`) and never load the model.
- **Configuration files are size-capped.** Specs, probe packs and model cards
  above 5 MB are refused (`PRAMANA_MAX_YAML_BYTES` changes the limit), and
  `builtin:` probe names must name a pack that ships with Pramana.
- **Agent output shown on a terminal is escaped.** When the sandbox asks a person to approve a request (`approver: ask`), and when `pramana scan-trace` prints signals, every character outside printable ASCII is shown as an escape, so an agent cannot use terminal control sequences or right-to-left overrides to change what the operator reads.
- **Model output is untrusted text.** The HTML report escapes everything it
  shows, so an answer containing HTML or script is displayed, never run. The
  report also carries a Content-Security-Policy that forbids every script,
  remote load, form and frame, so even an escaping bug could not run code or
  send data anywhere.
- **CSV exports cannot carry formulas.** A cell that would start with `=`, `+`,
  `-`, `@` or a tab is written with a leading apostrophe, so text from a model's
  answer or a trace cannot run as a formula when a reviewer opens the risk
  register in Excel, Numbers or Google Sheets (CWE-1236). Plain numbers are
  left as they are.
- **Audit packs from someone else are untrusted data.** `pramana verify` only
  reads files inside the pack, and the dashboard shows a pack's text as plain
  text, so it cannot load images or links from it. Bare web and e-mail
  addresses, which Streamlit would otherwise turn into links, are defanged with
  an invisible word joiner, and the one-click *Deploy* button is hidden so a
  pack is never published by accident.

## CI

- Workflows run with a read-only token (`permissions: contents: read`), use no
  repository secrets, and do not run on `pull_request_target`.
- Third-party actions are pinned to full commit SHAs of their official
  releases, so a moved tag cannot change what runs.
- `actions/checkout` does not keep the token in the working copy
  (`persist-credentials: false`), so it cannot end up in an uploaded artifact.
- The composite action passes its inputs to the shell as environment
  variables, never as script text.

- CodeQL (Python and Actions, `security-extended`), `bandit` and `pip-audit` run
  on every push; Dependabot proposes dependency and action updates weekly.
- Only three jobs get more than a read-only token, each with exactly the
  permission it needs (publishing, the GitHub release, CodeQL results). A test
  fails if any other job gains a permission or any action is not pinned to a
  full commit SHA.

## Proving who produced an audit pack

The hash chain proves a pack is internally consistent, and `pramana sign` proves
who holds a key. Neither stops someone from editing inputs and re-running the audit
on a laptop. Running the audit in CI with `attest: "true"` in the GitHub Action
closes that gap: GitHub signs the pack's `ledger.jsonl`, `results.json` and
`report.html` with a short-lived Sigstore certificate that names the repository,
commit, workflow and run. No signing key exists to steal or leak.

```bash
pramana verify pramana-audit --attested-by your-org/your-repo
```

This checks every file against the ledger, then asks the GitHub CLI to verify the
ledger's attestation, and prints the workflow and commit that produced it. Any edit
to the pack, or a pack built anywhere else, fails.

## Verifying a release

Releases are built by `.github/workflows/release.yml` from a tagged commit, in
GitHub Actions, never on a laptop. Each file on the
[Releases page](https://github.com/Tejascodz/pramana/releases) has a
build-provenance attestation signed with Sigstore, and the release lists
`SHA256SUMS` for every file. To check a wheel you downloaded:

```bash
gh attestation verify pramana_audit-0.6.0-py3-none-any.whl --repo Tejascodz/pramana
shasum -a 256 -c SHA256SUMS
```

If PyPI publishing is switched on later, it uses Trusted Publishing, so no
long-lived API token exists that could be stolen.

## Dependencies

The package and every optional extra had no known vulnerable dependencies
when 0.6.0 was released (`pip-audit`, run in CI on every push). Minimum
versions sit above known advisories (Jinja2 3.1.6, scikit-learn 1.5).

## Reporting a problem

Please report security issues privately through **Report a vulnerability** on the
repository's *Security* tab rather than in a public issue.

## Checking it yourself

```bash
pip install bandit pip-audit
bandit -r src dashboard examples        # static analysis
pip-audit                               # known-vulnerable dependencies
gitleaks git .                          # secrets in the full git history
pytest tests/test_security.py tests/test_input_safety.py   # the properties on this page
```
