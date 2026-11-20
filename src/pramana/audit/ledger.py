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
import os
import re
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pramana import safefs
from pramana.safeio import strict_json

LEDGER_NAME = "ledger.jsonl"
RUN_RECORDINGS = ("llm_replay.jsonl", "agent_sandbox_trace.jsonl")
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


class LedgerError(RuntimeError):
    """The ledger cannot accept more entries (an earlier write to it failed)."""


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return sha256_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class EvidenceLedger:
    """Writes evidence into a pack and records each file in the hash-chained ledger.

    The pack folder is trusted as given; everything inside it is reached without
    following links (see :mod:`pramana.safefs`), so a prepared pack cannot redirect a
    write or a clean-up outside it. Entries are appended one at a time under a lock,
    and an entry joins the in-memory chain only after it is on disk. If a write fails,
    the ledger refuses further entries rather than continuing a broken chain.
    """

    def __init__(self, pack_dir: Path):
        self.pack_dir = Path(pack_dir)
        self.path = self.pack_dir / LEDGER_NAME
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._failed: str | None = None
        with safefs.open_dir(self.pack_dir, EVIDENCE_DIR):
            pass  # creates the pack and evidence/ folders, refusing links
        self._clear_stale_evidence()
        safefs.write_bytes(self.pack_dir, LEDGER_NAME, b"")

    def _clear_stale_evidence(self) -> None:
        """Remove evidence left by an earlier run into the same folder.

        A new ledger starts empty, so any evidence file already on disk would be unrecorded
        and fail verification. Only Pramana's own files are touched: ``*.json`` directly
        inside ``evidence/<n>-<stage>/`` folders, the old signature and run recordings.
        A stage folder that is a link, or a ``.json`` entry that is a folder, is refused.
        """
        with safefs.open_dir(self.pack_dir, EVIDENCE_DIR, create=False) as evidence:
            stages = [n for n in evidence.names() if _STAGE_DIR.match(n)]
        for stage in stages:
            with safefs.open_dir(self.pack_dir, f"{EVIDENCE_DIR}/{stage}", create=False) as folder:
                for name in folder.names():
                    if name.endswith(".json"):
                        safefs.remove_file(folder, name)
        with safefs.open_dir(self.pack_dir, create=False) as pack:
            # The old signature signed the previous ledger, not this one. Recordings are
            # written only when a run has them: a re-run without LLM calls or sandbox runs
            # must not leave the previous run's copy behind, unrecorded.
            for name in (SIGNATURE_NAME_IF_ANY, *RUN_RECORDINGS):
                safefs.remove_file(pack, name)

    @property
    def root_hash(self) -> str | None:
        return self.entries[-1]["entry_hash"] if self.entries else None

    def _rel(self, rel_path: str | Path) -> str:
        """``rel_path`` as a plain path inside the pack; refuses anything that leaves it."""
        try:
            return "/".join(safefs._parts(rel_path))
        except safefs.UnsafePathError as exc:
            raise ValueError(f"refusing to write outside the audit pack: {rel_path}") from exc

    def _append(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Add one entry: on disk first, then to the in-memory chain. Call with the lock."""
        if self._failed:
            raise LedgerError(
                f"the ledger stopped accepting entries after a failed write ({self._failed}); "
                "start the audit again"
            )
        entry = dict(entry)
        entry["seq"] = len(self.entries) + 1
        entry["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry["prev_hash"] = self.root_hash
        entry["entry_hash"] = _entry_hash(entry)
        line = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
        try:
            safefs.append_bytes(self.pack_dir, LEDGER_NAME, line)
        except BaseException as exc:
            # The line may be partly on disk: no later entry can chain onto it reliably.
            self._failed = f"{type(exc).__name__}: {exc}"
            raise
        self.entries.append(entry)
        return entry

    def add_json(self, stage: str, name: str, data: Any) -> str:
        """Write JSON evidence inside the pack and record its hash."""
        rel = self._rel(Path(EVIDENCE_DIR) / stage / f"{name}.json")
        payload = canonical_json(data)
        with self._lock:
            safefs.write_bytes(self.pack_dir, rel, payload)
            digest = sha256_bytes(payload)
            self._append(
                {"stage": stage, "kind": "evidence", "name": name, "path": rel, "sha256": digest}
            )
        return digest

    def add_text(self, stage: str, name: str, rel_path: str, text: str) -> str:
        """Write a text file inside the pack (e.g. a JSONL replay file) and record its hash."""
        rel = self._rel(rel_path)
        payload = text.encode("utf-8")
        with self._lock:
            safefs.write_bytes(self.pack_dir, rel, payload)
            digest = sha256_bytes(payload)
            self._append(
                {"stage": stage, "kind": "evidence", "name": name, "path": rel, "sha256": digest}
            )
        return digest

    def add_pack_file(self, stage: str, name: str, rel_path: str) -> str:
        """Record a file already written inside the pack (e.g. the report)."""
        rel = self._rel(rel_path)
        with self._lock:
            digest = sha256_bytes(safefs.read_bytes(self.pack_dir, rel))
            self._append(
                {"stage": stage, "kind": "evidence", "name": name, "path": rel, "sha256": digest}
            )
        return digest

    def add_external(self, stage: str, label: str, path: Path) -> str:
        """Fingerprint an artifact that stays outside the pack (model, dataset, policy).

        Only the file name is stored, never the full path, so packs can be shared.
        """
        path = Path(path)
        digest = sha256_file(path)
        with self._lock:
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


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _entry_problem(entry: Any) -> str | None:
    """Why a ledger line is not a well-formed entry, or None if it is."""
    if not isinstance(entry, dict):
        return f"is a JSON {type(entry).__name__}, not an entry"
    if not isinstance(entry.get("seq"), int) or isinstance(entry.get("seq"), bool):
        return "has no whole-number seq"
    for key in ("entry_hash", "kind"):
        if not isinstance(entry.get(key), str):
            return f"has no text {key}"
    if entry.get("prev_hash") is not None and not isinstance(entry["prev_hash"], str):
        return "has a prev_hash that is not text"
    if entry["kind"] == "evidence":
        if not isinstance(entry.get("path"), str) or not entry["path"]:
            return "has no text path"
        if not isinstance(entry.get("sha256"), str) or not _HEX64.match(entry["sha256"]):
            return "has no valid sha256"
    return None


def _hash_evidence(pack_dir: Path, root: Path, rel: str) -> tuple[str | None, str | None]:
    """(sha256, None) for an evidence file inside the pack, or (None, problem)."""
    if rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":"):
        return None, "evidence path points outside the pack"
    try:
        target = (pack_dir / rel).resolve()
    except (OSError, RuntimeError, ValueError):
        return None, "evidence path cannot be resolved"
    if not target.is_relative_to(root):
        return None, "evidence path points outside the pack"
    try:
        mode = target.stat().st_mode
    except FileNotFoundError:
        return None, "evidence file missing"
    except OSError as exc:
        return None, f"evidence file cannot be read ({exc.strerror or exc})"
    if not stat.S_ISREG(mode):
        return None, "evidence path is not a regular file"
    try:
        return sha256_file(target), None
    except OSError as exc:
        return None, f"evidence file cannot be read ({exc.strerror or exc})"


def verify_pack(pack_dir: Path) -> tuple[bool, list[str]]:
    """Recompute the chain and every in-pack evidence hash.

    A malformed or hostile pack is reported as problems, never raised as an exception.
    """
    pack_dir = Path(pack_dir)
    ledger = pack_dir / LEDGER_NAME
    try:
        ledger_mode = os.lstat(ledger).st_mode
    except FileNotFoundError:
        return False, [f"{LEDGER_NAME} not found"]
    except OSError as exc:
        return False, [f"{LEDGER_NAME} cannot be read ({exc.strerror or exc})"]
    if not stat.S_ISREG(ledger_mode):
        return False, [f"{LEDGER_NAME} is not a regular file"]
    try:
        raw = ledger.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False, [f"{LEDGER_NAME} is not valid UTF-8 text"]
    except OSError as exc:
        return False, [f"{LEDGER_NAME} cannot be read ({exc.strerror or exc})"]

    problems: list[str] = []
    try:
        root = pack_dir.resolve()
    except OSError as exc:
        return False, [f"the pack folder cannot be resolved ({exc.strerror or exc})"]
    prev = None
    recorded: set[str] = set()
    lines = [line for line in text.splitlines() if line.strip()]
    for expected_seq, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except ValueError:
            problems.append(f"ledger line {expected_seq}: not valid JSON")
            prev = None
            continue
        malformed = _entry_problem(entry)
        if malformed:
            problems.append(f"ledger line {expected_seq}: {malformed}")
            prev = entry.get("entry_hash") if isinstance(entry, dict) else None
            continue
        label = f"entry {entry['seq']} ({entry.get('name')})"
        if entry["seq"] != expected_seq:
            problems.append(f"{label}: sequence gap, expected {expected_seq}")
        if entry.get("prev_hash") != prev:
            problems.append(f"{label}: chain broken (prev_hash mismatch)")
        if _entry_hash(entry) != entry["entry_hash"]:
            problems.append(f"{label}: entry was modified")
        if entry["kind"] == "evidence":
            recorded.add(entry["path"])
            digest, problem = _hash_evidence(pack_dir, root, entry["path"])
            if problem:
                problems.append(f"{label}: {problem}")
            elif digest != entry["sha256"]:
                problems.append(f"{label}: evidence file content changed")
        prev = entry["entry_hash"]

    # Every file in the pack must be recorded in the ledger, not only those under
    # evidence/. Otherwise cutting the tail off the ledger (where results.json and the
    # report are recorded) leaves a valid-looking chain, and results.json could then be
    # edited freely (found in the 0.7.8 review: a BLOCK was turned into a PASS).
    try:
        files = sorted(pack_dir.rglob("*"))
    except OSError as exc:
        files = []
        problems.append(f"the pack folder cannot be listed ({exc.strerror or exc})")
    for f in files:
        try:
            if not f.is_file() or f.name in UNSEALED_FILES or f.name in OS_METADATA:
                continue
        except OSError:
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
