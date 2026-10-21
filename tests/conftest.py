from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
AUDIT_DATE = date(2026, 10, 21)


@pytest.fixture(scope="session")
def credit_example(tmp_path_factory) -> Path:
    """A private copy of the credit-scoring case study with data and model built."""
    target = tmp_path_factory.mktemp("credit") / "credit_scoring"
    shutil.copytree(
        EXAMPLES / "credit_scoring",
        target,
        ignore=shutil.ignore_patterns("data", "model.joblib", "__pycache__"),
    )
    subprocess.run(
        [sys.executable, str(target / "build_model.py")], check=True, capture_output=True
    )
    return target


@pytest.fixture(scope="session")
def credit_audit(credit_example, tmp_path_factory):
    from pramana.audit.engine import run_audit
    from pramana.reporting import write_outputs
    from pramana.spec import load_spec

    out = tmp_path_factory.mktemp("pack-credit")
    result = run_audit(load_spec(credit_example / "audit.yaml"), out, audit_date=AUDIT_DATE)
    paths = write_outputs(result, out, ledger=result.ledger)
    return result, out, paths


@pytest.fixture(scope="session")
def chatbot_audit(tmp_path_factory):
    from pramana.audit.engine import run_audit
    from pramana.spec import load_spec

    out = tmp_path_factory.mktemp("pack-chatbot")
    return run_audit(
        load_spec(EXAMPLES / "support_chatbot" / "audit.yaml"), out, audit_date=AUDIT_DATE
    )


@pytest.fixture(scope="session")
def agent_audit(tmp_path_factory):
    from pramana.audit.engine import run_audit
    from pramana.spec import load_spec

    out = tmp_path_factory.mktemp("pack-agent")
    return run_audit(
        load_spec(EXAMPLES / "agent_traces" / "audit.yaml"), out, audit_date=AUDIT_DATE
    )
