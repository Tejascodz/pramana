.PHONY: install test lint example audits verify dashboard docs clean live-model live-baseline live-guarded live-audit

install:
	pip install -e ".[dev,dashboard]"

test:
	pytest

lint:
	ruff check src tests dashboard examples

example:
	python examples/credit_scoring/build_model.py

audits: example
	-pramana run examples/credit_scoring/audit.yaml --out packs/credit_scoring
	-pramana run examples/support_chatbot/audit.yaml --out packs/support_chatbot
	-pramana run examples/agent_traces/audit.yaml --out packs/agent_traces

verify:
	for p in packs/*; do pramana verify $$p; done

live-model:
	ollama pull llama3.2:3b

live-baseline:
	python examples/live_assistant/niva_app.py --mode baseline --port 8800

live-guarded:
	python examples/live_assistant/niva_app.py --mode guarded --port 8801

live-audit:
	-pramana run examples/live_assistant/audit_baseline.yaml --out packs/live_baseline
	-pramana run examples/live_assistant/audit_guarded.yaml --out packs/live_guarded
	pramana diff packs/live_baseline packs/live_guarded

dashboard:
	streamlit run dashboard/app.py -- --pack packs/credit_scoring

docs:
	pramana controls --markdown > docs/control-mapping.md

clean:
	rm -rf packs build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
