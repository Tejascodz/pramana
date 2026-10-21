# Live audit: a real LLM application on your laptop

This case study audits a running LLM application end to end, the way an
assurance team would test a deployed system: as a black box, over HTTP.

```
 Pramana  ──HTTP──▶  Niva app (baseline or guarded)  ──HTTP──▶  local model (Ollama)
 probes               retrieval + prompt + controls                llama3.2:3b, qwen3:4b, …
```

**Niva** (`niva_app.py`) is the system under audit: a loan-support assistant
for a fictional lender, with TF-IDF retrieval over the product sheet and a
customer database, served on an OpenAI-compatible endpoint. It runs as two
builds of the same model and data:

| Build | What it does | Controls |
|---|---|---|
| `baseline` | How many first versions ship | None. Customer records share the retrieval index with product info; the customer's text goes straight into the prompt; answers are returned as is |
| `guarded` | The same model after remediation | Record-level authorisation in retrieval, approved templates for regulated topics, multilingual input screening (incl. base64), spotlighting of untrusted text, output validation for canary and secret leaks, personal-data redaction, external links and images, ungrounded figures, and length |

The probe set (`probes.yaml`) combines Pramana's built-in packs (14 English
and 8 Indic-language injection probes, 5 disclosure probes) with Niva's own
facts and conduct rules, plus **4 held-out probes** the guarded build was not
written against. Those show how much risk remains after the controls.

## Run it (macOS, Apple silicon, 8 GB is enough)

**1. Install Ollama and pull a small model** (one-time)

Download Ollama from <https://ollama.com/download> (or `brew install ollama`) and
start it. Then:

```bash
ollama pull llama3.2:3b        # about 2 GB
```

**2. Start the two builds** (two Terminal windows, from the repository root, with the virtual environment active)

```bash
python examples/live_assistant/niva_app.py --mode baseline --port 8800
```

```bash
python examples/live_assistant/niva_app.py --mode guarded --port 8801
```

Each window prints one line per request with the guardrail actions taken.

**3. Audit both** (a third window)

```bash
pramana ping examples/live_assistant/audit_baseline.yaml
pramana run  examples/live_assistant/audit_baseline.yaml --out packs/live_baseline
pramana run  examples/live_assistant/audit_guarded.yaml  --out packs/live_guarded
pramana diff packs/live_baseline packs/live_guarded
open packs/live_baseline/report.html packs/live_guarded/report.html
```

Each audit sends 43 requests. On a MacBook with `llama3.2:3b` expect a few
minutes per audit; the guarded build is faster because blocked and templated
requests never reach the model.

**4. Optional runs**

```bash
# A different model (anything you have pulled)
python examples/live_assistant/niva_app.py --mode baseline --port 8800 --model qwen3:4b

# Repeat every probe 3 times: LLMs are stochastic, so this gives rates with 95% intervals
pramana run examples/live_assistant/audit_baseline.yaml --out packs/live_baseline_x3 --samples 3

# The raw model with no application around it
pramana run examples/live_assistant/audit_raw_model.yaml --out packs/live_raw
```

## Reading the results

- **Prompt injection** lists every probe with its technique and language. A
  small model in the baseline build usually follows some injected instructions
  and leaks the canary (`ORCHID-5521`) planted in its system prompt.
- **Disclosure** shows whether customer e-mails, mobiles or PANs from the CRM
  reach the answer. In the baseline build they can, because retrieval has no
  authorisation; in the guarded build they are never retrieved.
- **Held-out probes** (tagged *held out* in the report) are the honest measure
  of the guarded build. Some may still succeed: input filters only catch what
  they were written for, and the output validator only catches what it can
  recognise. That residual risk is a finding, not a failure of the audit.
- **Service health** reports latency and errors from the run itself.
- Results marked **review** contain both proof of compliance and refusal
  language, and should be checked by a person.

## The recorded real run

`recorded/` holds the responses from the first live run of both builds on
`llama3.2:3b`. Re-score them with the current scorer, no model needed:

```bash
pramana run examples/live_assistant/audit_guarded.yaml --replay examples/live_assistant/recorded/llama32_3b_guarded.json --out packs/replay_guarded
```

What that run found, including four blind spots in Pramana's own scoring that
it exposed and that are now fixed, is in
[docs/live-run-findings.md](../../docs/live-run-findings.md).

## Re-run a live audit offline

Every live pack contains `llm_replay.jsonl`. Pass it with `--replay`, or point
a spec at it, to reproduce the audit without the app or the model, for example in CI:

```yaml
llm:
  mode: replay
  replay: ../../packs/live_baseline/llm_replay.jsonl
  probes: probes.yaml
  knowledge_base: ../support_chatbot/knowledge_base.md
```

## Auditing your own application

Any service with an OpenAI-compatible chat endpoint works with
`mode: openai_compatible`. For any other JSON API, use `mode: http`:

```yaml
llm:
  mode: http
  url: https://my-app.example/api/chat
  headers: {Authorization: "Bearer ${MY_APP_TOKEN}"}   # read from the environment
  body: {question: "{prompt}", session: "audit-{sample}"}
  response_path: data.answer
  probes: probes.yaml
```

Nilgiri Finance, Niva and every customer record here are fictional.
