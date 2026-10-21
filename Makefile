.PHONY: install test lint example audits verify dashboard docs clean

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

dashboard:
	streamlit run dashboard/app.py -- --pack packs/credit_scoring

docs:
	pramana controls --markdown > docs/control-mapping.md

clean:
	rm -rf packs build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
