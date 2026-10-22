"""Signed audit packs: provenance and non-repudiation on top of the hash chain."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cryptography")  # signing is an optional feature

from pramana.audit.engine import run_audit  # noqa: E402
from pramana.audit.signing import (  # noqa: E402
    SigningError,
    generate_keypair,
    sign_pack,
    verify_pack_signature,
)
from pramana.cli import main  # noqa: E402
from pramana.reporting import write_outputs  # noqa: E402
from pramana.spec import load_spec  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def pack(tmp_path):
    spec = load_spec(ROOT / "examples" / "agent_traces" / "audit.yaml")
    result = run_audit(spec, tmp_path / "pack")
    write_outputs(result, tmp_path / "pack", ledger=result.ledger)
    return tmp_path / "pack"


def test_sign_then_verify_with_the_matching_key(pack):
    private, public = generate_keypair()
    sign_pack(pack, private)
    ok, problems = verify_pack_signature(pack, public)
    assert ok and problems == []


def test_a_different_key_is_rejected(pack):
    private, _ = generate_keypair()
    sign_pack(pack, private)
    _, other_public = generate_keypair()
    ok, problems = verify_pack_signature(pack, other_public)
    assert not ok and any("different key" in p for p in problems)


def test_tampering_after_signing_breaks_the_signature(pack):
    private, public = generate_keypair()
    sign_pack(pack, private)
    ledger = pack / "ledger.jsonl"
    ledger.write_text(ledger.read_text().replace("refund", "REFUND", 1), encoding="utf-8")
    ok, problems = verify_pack_signature(pack, public)
    assert not ok


def test_signing_refuses_an_already_tampered_pack(pack):
    results = pack / "results.json"
    results.write_text(results.read_text() + "\n/* edited */", encoding="utf-8")
    private, _ = generate_keypair()
    with pytest.raises(SigningError, match="fails verification"):
        sign_pack(pack, private)


def test_unsigned_pack_reports_clearly(pack):
    ok, problems = verify_pack_signature(pack)
    assert not ok and "not signed" in problems[0]


def test_cli_keygen_sign_and_verify(pack, tmp_path, capsys):
    assert main(["keygen", "--out-dir", str(tmp_path / "keys")]) == 0
    priv = tmp_path / "keys" / "pramana_ed25519.key"
    pub = tmp_path / "keys" / "pramana_ed25519.pub"
    assert priv.exists() and pub.exists()
    # private key is not world-readable
    assert (priv.stat().st_mode & 0o077) == 0

    assert main(["sign", str(pack), "--key", str(priv)]) == 0
    # plain verify now also checks the signature it finds
    assert main(["verify", str(pack)]) == 0
    # pinning the right public key passes, a wrong one fails (exit 2)
    assert main(["verify", str(pack), "--public-key", str(pub)]) == 0


def test_cli_require_signature_fails_on_unsigned(pack):
    assert main(["verify", str(pack), "--require-signature"]) == 2


def test_cli_verify_detects_a_wrong_pinned_key(pack, tmp_path):
    main(["keygen", "--out-dir", str(tmp_path / "k1")])
    main(["keygen", "--out-dir", str(tmp_path / "k2")])
    main(["sign", str(pack), "--key", str(tmp_path / "k1" / "pramana_ed25519.key")])
    assert (
        main(["verify", str(pack), "--public-key", str(tmp_path / "k2" / "pramana_ed25519.pub")])
        == 2
    )
