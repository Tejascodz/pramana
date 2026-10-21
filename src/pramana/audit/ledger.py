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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_NAME = "ledger.jsonl"
EVIDENCE_DIR = "evidence"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, indent=2, default=str, ensure_ascii=False).encode(
        "utf-8"
    )


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return sha256_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class EvidenceLedger:
    def __init__(self, pack_dir: Path):
        self.pack_dir = Path(pack_dir)
        self.pack_dir.mkdir(parents=True, exist_ok=True)
        (self.pack_dir / EVIDENCE_DIR).mkdir(exist_ok=True)
        self.path = self.pack_dir / LEDGER_NAME
        self.path.write_text("", encoding="utf-8")
        self.entries: list[dict[str, Any]] = []

    @property
    def root_hash(self) -> str | None:
        return self.entries[-1]["entry_hash"] if self.entries else None

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
        target = self.pack_dir / rel
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

    def add_pack_file(self, stage: str, name: str, rel_path: str) -> str:
        """Record a file already written inside the pack (e.g. the report)."""
        digest = sha256_file(self.pack_dir / rel_path)
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
            target = pack_dir / entry["path"]
            if not target.exists():
                problems.append(f"{label}: evidence file missing")
            elif sha256_file(target) != entry["sha256"]:
                problems.append(f"{label}: evidence file content changed")
        prev = entry.get("entry_hash")
    return not problems, problems
