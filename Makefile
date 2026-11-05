.PHONY: demos build release-check install test lint example audits verify dashboard docs clean live-model live-baseline live-guarded live-audit

install:
	pip install -e ".[dev,dashboard]"

test:
	pytest

lint:
	ruff check src tests dashboard examples
	ruff format --check src tests dashboard examples

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
	streamlit run dashboard/app.py --server.address 127.0.0.1 -- --pack packs/credit_scoring

docs:
	pramana controls --markdown > docs/control-mapping.md

clean:
	rm -rf packs build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# Copy the case studies into the package so `pramana demo` works after pip install.
demos:
	python -c "import shutil; ig = shutil.ignore_patterns('data', 'model.joblib', '__pycache__'); [shutil.copytree('examples/' + s, 'src/pramana/demos/' + d, ignore=ig, dirs_exist_ok=True) for s, d in [('credit_scoring', 'credit-scoring'), ('support_chatbot', 'support-chatbot'), ('agent_traces', 'agent-traces')]]"

build:
	python -m build
	twine check --strict dist/*

release-check: build
	python -m venv /tmp/pramana-release-check && /tmp/pramana-release-check/bin/pip install dist/*.whl
	cd /tmp && /tmp/pramana-release-check/bin/pramana demo --out /tmp/pramana-release-check-demo
