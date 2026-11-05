"""Tamper-evident evidence ledger.

Every piece of evidence is written to the audit pack and recorded in an
append-only JSONL ledger. Each entry stores the SHA-256 of the evidence and the
hash of the previous entry, so changing any evidence file, or editing, removing
or reordering ledger entries, breaks verification. The final entry hash acts as
the audit's root hash and is printed on the report.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pramana.safeio import strict_json

LEDGER_NAME = "ledger.jsonl"
EVIDENCE_DIR = "evidence"
# Evidence lives in evidence/<n>-<stage>/<name>.json (one folder per SMACTR stage).
_STAGE_DIR = re.compile(r"^\d-[a-z]+$")

# Detached signature written beside the ledger by `pramana sign` (optional).
# Named here so `verify` can detect it without importing the signing module
# (which needs the optional 'cryptography' dependency).
SIGNATURE_NAME_IF_ANY = "signature.json"
RESULTS_NAME = "results.json"
#: Files in a pack that are not sealed in its own ledger: the ledger itself and the
#: detached signature over it.
UNSEALED_FILES = {LEDGER_NAME, SIGNATURE_NAME_IF_ANY}
#: Metadata a file manager may drop into any folder; never read by Pramana.
OS_METADATA = {".DS_Store", "Thumbs.db", "desktop.ini"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(data: Any) -> bytes:
    return json.dumps(
        strict_json(data),
        sort_keys=True,
        indent=2,
        default=str,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return sha256_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class EvidenceLedger:
    def __init__(self, pack_dir: Path):
        self.pack_dir = Path(pack_dir)
        self.pack_dir.mkdir(parents=True, exist_ok=True)
        (self.pack_dir / EVIDENCE_DIR).mkdir(exist_ok=True)
        self._clear_stale_evidence()
        self.path = self.pack_dir / LEDGER_NAME
        self.path.write_text("", encoding="utf-8")
        self.entries: list[dict[str, Any]] = []

    def _clear_stale_evidence(self) -> None:
        """Remove evidence left by an earlier run into the same folder.

        A new ledger starts empty, so any evidence file already on disk would be unrecorded
        and fail verification. Only Pramana's own files are touched: ``*.json`` directly
        inside ``evidence/<n>-<stage>/`` folders.
        """
        for stage in (self.pack_dir / EVIDENCE_DIR).iterdir():
            if stage.is_dir() and _STAGE_DIR.match(stage.name):
                for f in stage.glob("*.json"):
                    f.unlink()
        stale_signature = self.pack_dir / SIGNATURE_NAME_IF_ANY
        if stale_signature.exists():
            stale_signature.unlink()  # it signed the previous ledger, not this one

    @property
    def root_hash(self) -> str | None:
        return self.entries[-1]["entry_hash"] if self.entries else None

    def _inside(self, rel_path: str | Path) -> Path:
        """The pack path for ``rel_path``; refuses anything that would land outside the pack."""
        root = self.pack_dir.resolve()
        target = (self.pack_dir / rel_path).resolve()
        if not target.is_relative_to(root):
            raise ValueError(f"refusing to write outside the audit pack: {rel_path}")
        return target

    def _append(self, entry: dict[str, Any]) -> dict[str, Any]:
        entry["seq"] = len(self.entries) + 1
        entry["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry["prev_hash"] = self.root_hash
        entry["entry_hash"] = _entry_hash(entry)
        self.entries.append(entry)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def add_json(self, stage: str, name: str, data: Any) -> str:
        """Write JSON evidence inside the pack and record its hash."""
        rel = Path(EVIDENCE_DIR) / stage / f"{name}.json"
        target = self._inside(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_json(data)
        target.write_bytes(payload)
        digest = sha256_bytes(payload)
        self._append(
            {
                "stage": stage,
                "kind": "evidence",
                "name": name,
                "path": rel.as_posix(),
                "sha256": digest,
            }
        )
        return digest

    def add_text(self, stage: str, name: str, rel_path: str, text: str) -> str:
        """Write a text file inside the pack (e.g. a JSONL replay file) and record its hash."""
        target = self._inside(rel_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = text.encode("utf-8")
        target.write_bytes(payload)
        digest = sha256_bytes(payload)
        self._append(
            {"stage": stage, "kind": "evidence", "name": name, "path": rel_path, "sha256": digest}
        )
        return digest

    def add_pack_file(self, stage: str, name: str, rel_path: str) -> str:
        """Record a file already written inside the pack (e.g. the report)."""
        digest = sha256_file(self._inside(rel_path))
        self._append(
            {"stage": stage, "kind": "evidence", "name": name, "path": rel_path, "sha256": digest}
        )
        return digest

    def add_external(self, stage: str, label: str, path: Path) -> str:
        """Fingerprint an artifact that stays outside the pack (model, dataset, policy).

        Only the file name is stored, never the full path, so packs can be shared.
        """
        path = Path(path)
        digest = sha256_file(path)
        self._append(
            {
                "stage": stage,
                "kind": "artifact",
                "name": label,
                "path": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
            }
        )
        return digest


def verify_pack(pack_dir: Path) -> tuple[bool, list[str]]:
    """Recompute the chain and every in-pack evidence hash."""
    pack_dir = Path(pack_dir)
    ledger = pack_dir / LEDGER_NAME
    if not ledger.exists():
        return False, [f"{LEDGER_NAME} not found"]
    problems: list[str] = []
    root = pack_dir.resolve()
    prev = None
    lines = [line for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    for expected_seq, line in enumerate(lines, 1):
        entry = json.loads(line)
        label = f"entry {entry.get('seq')} ({entry.get('name')})"
        if entry.get("seq") != expected_seq:
            problems.append(f"{label}: sequence gap, expected {expected_seq}")
        if entry.get("prev_hash") != prev:
            problems.append(f"{label}: chain broken (prev_hash mismatch)")
        if _entry_hash(entry) != entry.get("entry_hash"):
            problems.append(f"{label}: entry was modified")
        if entry.get("kind") == "evidence":
            target = (pack_dir / entry["path"]).resolve()
            if not target.is_relative_to(root):
                problems.append(f"{label}: evidence path points outside the pack")
            elif not target.exists():
                problems.append(f"{label}: evidence file missing")
            elif sha256_file(target) != entry["sha256"]:
                problems.append(f"{label}: evidence file content changed")
        prev = entry.get("entry_hash")

    # Every file in the pack must be recorded in the ledger, not only those under
    # evidence/. Otherwise cutting the tail off the ledger (where results.json and the
    # report are recorded) leaves a valid-looking chain, and results.json could then be
    # edited freely (found in the 0.7.8 review: a BLOCK was turned into a PASS).
    recorded = {
        json.loads(line).get("path") for line in lines if json.loads(line).get("kind") == "evidence"
    }
    for f in sorted(pack_dir.rglob("*")):
        if not f.is_file() or f.name in UNSEALED_FILES or f.name in OS_METADATA:
            continue
        rel = f.relative_to(pack_dir).as_posix()
        if rel not in recorded:
            where = "in evidence" if rel.startswith(f"{EVIDENCE_DIR}/") else "in the pack"
            problems.append(f"unrecorded file {where}: {rel}")
    if RESULTS_NAME not in recorded:
        problems.append(
            f"{RESULTS_NAME} is not recorded in the ledger (pack incomplete or truncated)"
        )
    return not problems, problems
