"""Cryptographic signing of audit packs.

The evidence ledger (``ledger.jsonl``) is a hash chain: changing any evidence
file or ledger line breaks ``pramana verify``. That proves a pack is internally
consistent, but not *who* produced it, and nothing stops someone rebuilding the
whole chain from altered evidence.

Signing closes that gap. The holder of a private key signs the pack's root hash
and a digest of the ledger, producing ``signature.json``. A third party with the
matching public key can then confirm the pack was sealed by that key holder and
has not been rebuilt. This is provenance and non-repudiation on top of the
chain's tamper-evidence.

Signing is optional and needs the ``cryptography`` package
(``pip install "pramana[signing]"``). Ed25519 keys are small, fast and standard.

What a valid signature proves, and does not:
* **Proves:** the pack was signed by the holder of the private key, and the
  ledger and its evidence have not changed since (the chain is re-verified first).
* **Does not prove:** that the audit's conclusions are correct, or *which* party
  signed — for that, pin the expected public key and pass it to ``verify``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pramana.audit.ledger import LEDGER_NAME, sha256_bytes, verify_pack

SIGNATURE_NAME = "signature.json"
ALGORITHM = "ed25519"


class SigningError(RuntimeError):
    """Raised when signing or signature verification cannot proceed."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised via the error path
        raise SigningError(
            "Signing needs the 'cryptography' package. Install it with: "
            'pip install "pramana[signing]"'
        ) from exc
    return ed25519, serialization


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_pem, public_key_pem) for a fresh Ed25519 key."""
    ed25519, serialization = _require_crypto()
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _ledger_root_and_digest(pack_dir: Path) -> tuple[str, str]:
    """The pack's root hash (last ledger entry) and the sha256 of the ledger file."""
    ledger = Path(pack_dir) / LEDGER_NAME
    if not ledger.exists():
        raise SigningError(f"{LEDGER_NAME} not found in {pack_dir}")
    raw = ledger.read_bytes()
    lines = [line for line in raw.decode("utf-8").splitlines() if line.strip()]
    if not lines:
        raise SigningError("ledger is empty; nothing to sign")
    root = json.loads(lines[-1]).get("entry_hash")
    if not root:
        raise SigningError("ledger's final entry has no entry_hash")
    return root, sha256_bytes(raw)


def _payload(pack_dir: Path, signed_at: str) -> dict[str, Any]:
    root, digest = _ledger_root_and_digest(pack_dir)
    return {
        "pack": Path(pack_dir).name,
        "ledger_root": root,
        "ledger_sha256": digest,
        "signed_at": signed_at,
    }


def _payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_pack(pack_dir: str | Path, private_key_pem: bytes, signed_at: str | None = None) -> dict:
    """Sign a pack's root and ledger digest; write and return ``signature.json``.

    The pack's hash chain is re-verified first: an already-tampered pack is not signed.
    """
    ed25519, serialization = _require_crypto()
    pack_dir = Path(pack_dir)
    ok, problems = verify_pack(pack_dir)
    if not ok:
        raise SigningError(
            "refusing to sign a pack that fails verification: " + "; ".join(problems)
        )

    private = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SigningError("private key is not an Ed25519 key")

    payload = _payload(
        pack_dir, signed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    signature = private.sign(_payload_bytes(payload))
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    record = {
        "algorithm": ALGORITHM,
        "public_key": public_pem.decode("utf-8"),
        "payload": payload,
        "signature": signature.hex(),
    }
    (pack_dir / SIGNATURE_NAME).write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def verify_pack_signature(
    pack_dir: str | Path, expected_public_key_pem: bytes | None = None
) -> tuple[bool, list[str]]:
    """Verify ``signature.json``: chain valid, payload matches, signature authentic.

    If ``expected_public_key_pem`` is given, the pack must be signed by exactly that
    key (provenance). Otherwise the key embedded in the signature is used, which
    proves integrity and that *some* holder of that key signed it.
    """
    ed25519, serialization = _require_crypto()
    pack_dir = Path(pack_dir)
    sig_path = pack_dir / SIGNATURE_NAME
    if not sig_path.exists():
        return False, [f"{SIGNATURE_NAME} not found; pack is not signed"]

    problems: list[str] = []
    ok, chain_problems = verify_pack(pack_dir)
    if not ok:
        problems.extend(chain_problems)

    record = json.loads(sig_path.read_text(encoding="utf-8"))
    if record.get("algorithm") != ALGORITHM:
        return False, [f"unsupported signature algorithm {record.get('algorithm')!r}"]

    # The signed payload must still describe the current pack.
    try:
        current = _payload(pack_dir, record["payload"]["signed_at"])
    except SigningError as exc:
        return False, [str(exc)]
    for field in ("ledger_root", "ledger_sha256"):
        if record["payload"].get(field) != current.get(field):
            problems.append(
                f"signature {field} does not match the pack (pack was altered or rebuilt)"
            )

    embedded_pem = record["public_key"].encode("utf-8")
    if expected_public_key_pem is not None:
        if _normalise(expected_public_key_pem) != _normalise(embedded_pem):
            problems.append("pack is signed by a different key than the one provided")
    public = serialization.load_pem_public_key(embedded_pem)
    if not isinstance(public, ed25519.Ed25519PublicKey):
        return False, ["signature public key is not an Ed25519 key"]
    try:
        public.verify(bytes.fromhex(record["signature"]), _payload_bytes(record["payload"]))
    except Exception:  # noqa: BLE001 - any failure means the signature is invalid
        problems.append("signature is not valid for this payload and key")

    return (not problems), problems


def _normalise(pem: bytes) -> bytes:
    return b"".join(pem.split())
