"""`pramana verify --attested-by` checks the GitHub attestation through the gh CLI.

A stand-in `gh` on PATH plays GitHub's role, so these tests check Pramana's side:
the right command, the ledger as subject, and the verdicts. A real attestation can
only be made inside GitHub Actions; see SECURITY.md for checking one.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest
import yaml

from pramana.cli import main

ROOT = Path(__file__).resolve().parents[1]
CERT = {
    "sourceRepositoryURI": "https://github.com/acme/models",
    "sourceRepositoryDigest": "0123456789abcdef0123",
    "buildSignerURI": "https://github.com/acme/models/.github/workflows/audit.yml@refs/heads/main",
    "runInvocationURI": "https://github.com/acme/models/actions/runs/42/attempts/1",
}


def _fake_gh(tmp: Path, ok: bool, log: Path) -> Path:
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    payload = json.dumps([{"verificationResult": {"signature": {"certificate": CERT}}}])
    gh.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{log}"\n'
        + (
            f"echo '{payload}'\nexit 0\n" if ok else "echo 'no matching attestations' >&2\nexit 1\n"
        ),
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    return bin_dir


@pytest.fixture()
def pack(tmp_path):
    assert main(["demo", "agent", "--out", str(tmp_path / "demo")]) == 0
    return tmp_path / "demo" / "agent-traces" / "pack"


@pytest.mark.skipif(os.name == "nt", reason="uses a shell-script stand-in for gh")
def test_an_attested_pack_reports_who_built_it(tmp_path, pack, monkeypatch, capsys):
    log = tmp_path / "args.txt"
    monkeypatch.setenv("PATH", f"{_fake_gh(tmp_path, True, log)}{os.pathsep}{os.environ['PATH']}")
    assert main(["verify", str(pack), "--attested-by", "acme/models"]) == 0
    out = capsys.readouterr().out
    assert "ATTESTED" in out and "workflows/audit.yml" in out and "0123456789ab" in out
    args = log.read_text().split()
    assert args[:3] == ["attestation", "verify", str(pack / "ledger.jsonl")]
    assert args[3:5] == ["--repo", "acme/models"]


@pytest.mark.skipif(os.name == "nt", reason="uses a shell-script stand-in for gh")
def test_a_pack_without_a_valid_attestation_fails(tmp_path, pack, monkeypatch, capsys):
    log = tmp_path / "args.txt"
    monkeypatch.setenv("PATH", f"{_fake_gh(tmp_path, False, log)}{os.pathsep}{os.environ['PATH']}")
    assert main(["verify", str(pack), "--attested-by", "acme/models"]) == 2
    assert "NOT ATTESTED" in capsys.readouterr().out


def test_a_tampered_pack_fails_before_the_attestation_is_checked(tmp_path, pack, monkeypatch):
    (pack / "results.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))  # gh would not even be found
    assert main(["verify", str(pack), "--attested-by", "acme/models"]) == 2


def test_missing_gh_is_a_clear_input_error(tmp_path, pack, monkeypatch, capsys):
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    assert main(["verify", str(pack), "--attested-by", "acme/models"]) == 3
    assert "GitHub CLI" in capsys.readouterr().err


def test_the_action_attests_the_ledger_with_a_pinned_action():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = {s.get("name"): s for s in action["runs"]["steps"]}
    attest = steps["Attest the audit pack"]
    assert attest["if"] == "inputs.attest == 'true'"
    assert re.search(r"@[0-9a-f]{40}$", attest["uses"])
    assert "ledger.jsonl" in attest["with"]["subject-path"]
    assert action["inputs"]["attest"]["default"] == "false"
