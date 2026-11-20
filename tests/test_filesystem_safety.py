"""Regression tests: no audit-pack, key or demo write can reach outside its folder.

Each test plants a symbolic link, hard link or wrong file type where Pramana writes,
deletes or reads, and checks two things: the operation is refused (or done safely),
and the file outside the folder is unchanged. Every one of these failed before 0.8.0.
"""

from __future__ import annotations

import os
import socket
import threading

import pytest

from pramana import safefs
from pramana.audit import ledger as ledger_mod
from pramana.audit.ledger import EvidenceLedger, verify_pack
from pramana.cli import main
from pramana.reporting import REPORT_FILES, write_outputs

posix_only = pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
MARKER = "outside file: must not change\n"


@pytest.fixture
def outside(tmp_path):
    """A file outside every folder Pramana is given, with known content."""
    target = tmp_path / "outside" / "precious.txt"
    target.parent.mkdir()
    target.write_text(MARKER)
    return target


# ---------------------------------------------------------------------------------------
# Report files
# ---------------------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize(
    "name", ["results.json", "risk_register.csv", "model_card.md", "report.html"]
)
def test_a_report_file_symlinked_outside_is_refused(chatbot_audit, tmp_path, outside, name):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / name).symlink_to(outside)
    with pytest.raises(safefs.UnsafePathError):
        write_outputs(chatbot_audit, pack)
    assert outside.read_text() == MARKER


@posix_only
def test_a_dangling_report_symlink_does_not_create_a_file_outside(chatbot_audit, tmp_path):
    pack, ghost = tmp_path / "pack", tmp_path / "ghost.json"
    pack.mkdir()
    (pack / "results.json").symlink_to(ghost)
    with pytest.raises(safefs.UnsafePathError):
        write_outputs(chatbot_audit, pack)
    assert not ghost.exists()


@posix_only
def test_a_hard_linked_report_file_is_replaced_not_written_through(
    chatbot_audit, tmp_path, outside
):
    pack = tmp_path / "pack"
    pack.mkdir()
    os.link(outside, pack / "results.json")
    write_outputs(chatbot_audit, pack)
    assert outside.read_text() == MARKER  # the other name keeps the old content
    assert (pack / "results.json").read_text().startswith("{")
    assert os.stat(pack / "results.json").st_ino != os.stat(outside).st_ino


def test_a_folder_at_a_report_path_stops_before_anything_is_written(chatbot_audit, tmp_path):
    pack = tmp_path / "pack"
    (pack / "model_card.md").mkdir(parents=True)
    with pytest.raises(safefs.UnsafePathError):
        write_outputs(chatbot_audit, pack)
    written = [n for n in REPORT_FILES.values() if (pack / n).is_file()]
    assert written == []  # no partial pack


@posix_only
def test_cli_run_refuses_a_report_symlink(tmp_path, outside, capsys):
    from conftest import EXAMPLES

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "ledger.jsonl").write_text("")  # an earlier pack, so --out is accepted
    (pack / "report.html").symlink_to(outside)
    spec = EXAMPLES / "support_chatbot" / "audit.yaml"
    assert main(["run", str(spec), "--out", str(pack), "--date", "2026-10-21"]) == 3
    assert outside.read_text() == MARKER
    assert "symbolic link" in capsys.readouterr().err


# ---------------------------------------------------------------------------------------
# Ledger construction and clean-up
# ---------------------------------------------------------------------------------------


@posix_only
def test_a_symlinked_stage_folder_is_refused_and_nothing_outside_is_deleted(tmp_path):
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "keep.json").write_text("{}")
    pack = tmp_path / "pack"
    (pack / "evidence").mkdir(parents=True)
    (pack / "evidence" / "1-scoping").symlink_to(outside_dir)
    with pytest.raises(safefs.UnsafePathError):
        EvidenceLedger(pack)
    assert (outside_dir / "keep.json").exists()


@posix_only
def test_a_symlinked_evidence_root_is_refused_and_nothing_outside_is_deleted(tmp_path):
    outside_dir = tmp_path / "outside"
    (outside_dir / "1-scoping").mkdir(parents=True)
    (outside_dir / "1-scoping" / "keep.json").write_text("{}")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "evidence").symlink_to(outside_dir)
    with pytest.raises(safefs.UnsafePathError):
        EvidenceLedger(pack)
    assert (outside_dir / "1-scoping" / "keep.json").exists()


@posix_only
def test_a_symlinked_ledger_file_is_not_truncated(tmp_path, outside):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "ledger.jsonl").symlink_to(outside)
    with pytest.raises(safefs.UnsafePathError):
        EvidenceLedger(pack)
    assert outside.read_text() == MARKER


@posix_only
def test_a_dangling_ledger_symlink_does_not_create_a_file_outside(tmp_path):
    pack, ghost = tmp_path / "pack", tmp_path / "ghost.jsonl"
    pack.mkdir()
    (pack / "ledger.jsonl").symlink_to(ghost)
    with pytest.raises(safefs.UnsafePathError):
        EvidenceLedger(pack)
    assert not ghost.exists()


def test_a_folder_named_like_evidence_is_refused_cleanly(tmp_path):
    pack = tmp_path / "pack"
    (pack / "evidence" / "1-scoping" / "odd.json").mkdir(parents=True)
    with pytest.raises(safefs.UnsafePathError, match="folder"):
        EvidenceLedger(pack)


def test_a_rerun_still_clears_stale_evidence(tmp_path):
    pack = tmp_path / "pack"
    first = EvidenceLedger(pack)
    first.add_json("1-scoping", "old", {"a": 1})
    second = EvidenceLedger(pack)
    assert not (pack / "evidence" / "1-scoping" / "old.json").exists()
    second.add_json("1-scoping", "new", {"a": 2})
    assert second.entries[0]["seq"] == 1


# ---------------------------------------------------------------------------------------
# Ledger appends: concurrency and failed writes
# ---------------------------------------------------------------------------------------


def test_concurrent_appends_keep_one_valid_chain(tmp_path, monkeypatch):
    """Two threads appending at once used to get the same sequence number."""
    real = ledger_mod._entry_hash
    barrier = threading.Barrier(2, timeout=2)

    def slow_hash(entry):
        try:
            barrier.wait()  # both threads are now inside an append together
        except threading.BrokenBarrierError:
            pass  # appends are serialised: the second thread never arrives
        return real(entry)

    monkeypatch.setattr(ledger_mod, "_entry_hash", slow_hash)
    pack = tmp_path / "pack"
    ledger = EvidenceLedger(pack)
    threads = [
        threading.Thread(target=ledger.add_json, args=("4-testing", f"t{i}", {"i": i}))
        for i in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    monkeypatch.setattr(ledger_mod, "_entry_hash", real)
    ledger.add_json("5-reflection", "after", {})
    seqs = [e["seq"] for e in ledger.entries]
    assert seqs == [1, 2, 3]
    ledger.add_json("1-scoping", "results", {})
    (pack / "results.json").write_text("{}")
    ledger.add_pack_file("6-reporting", "results", "results.json")
    ok, problems = verify_pack(pack)
    assert ok, problems


def test_a_failed_ledger_write_stops_the_ledger_instead_of_breaking_the_chain(tmp_path):
    pack = tmp_path / "pack"
    ledger = EvidenceLedger(pack)
    ledger_file = pack / "ledger.jsonl"
    ledger_file.unlink()
    ledger_file.mkdir()  # the next append cannot be written
    with pytest.raises((OSError, ValueError)):
        ledger.add_json("1-scoping", "first", {})
    ledger_file.rmdir()
    ledger_file.write_text("")
    with pytest.raises(ledger_mod.LedgerError):
        ledger.add_json("1-scoping", "second", {})
    assert ledger.entries == []
    assert ledger_file.read_text() == ""  # no entry with a gap or a broken chain


# ---------------------------------------------------------------------------------------
# Verification of malformed or hostile packs: problems, never exceptions
# ---------------------------------------------------------------------------------------


@pytest.fixture
def small_pack(tmp_path):
    pack = tmp_path / "pack"
    ledger = EvidenceLedger(pack)
    ledger.add_json("1-scoping", "scope", {"a": 1})
    (pack / "results.json").write_text("{}")
    ledger.add_pack_file("6-reporting", "results", "results.json")
    assert verify_pack(pack)[0]
    return pack


@pytest.mark.parametrize(
    "line",
    [
        b"{not json",
        b"[1, 2]",
        b"null",
        b"42",
        b'"text"',
        b'{"seq": 1, "kind": "evidence", "entry_hash": "x", "path": 7, "sha256": "0"}',
        b'{"seq": 1, "kind": "evidence", "entry_hash": "x", "path": null, "sha256": "0"}',
        b'{"seq": "1", "kind": "evidence", "entry_hash": "x"}',
        b"\xff\xfe not utf-8",
    ],
)
def test_a_malformed_ledger_line_is_a_problem_not_a_crash(small_pack, line):
    ledger_file = small_pack / "ledger.jsonl"
    ledger_file.write_bytes(line + b"\n" + ledger_file.read_bytes())
    ok, problems = verify_pack(small_pack)
    assert not ok and problems


def test_a_ledger_that_is_a_folder_is_a_problem_not_a_crash(tmp_path):
    (tmp_path / "pack" / "ledger.jsonl").mkdir(parents=True)
    ok, problems = verify_pack(tmp_path / "pack")
    assert not ok and "not a regular file" in problems[0]


def test_evidence_that_is_a_folder_is_a_problem_not_a_crash(small_pack):
    evidence = small_pack / "evidence" / "1-scoping" / "scope.json"
    evidence.unlink()
    evidence.mkdir()
    ok, problems = verify_pack(small_pack)
    assert not ok and any("not a regular file" in p for p in problems)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs Unix sockets")
def test_evidence_that_is_a_socket_is_a_problem_not_a_crash(small_pack):
    evidence = small_pack / "evidence" / "1-scoping" / "scope.json"
    evidence.unlink()
    if len(str(evidence)) > 100:  # socket paths are limited to ~104 bytes
        pytest.skip("temporary path too long for a Unix socket")
    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.bind(str(evidence))
        ok, problems = verify_pack(small_pack)
    finally:
        sock.close()
    assert not ok and any("not a regular file" in p for p in problems)


def test_a_malformed_public_key_in_a_signature_is_a_problem_not_a_crash(small_pack):
    pytest.importorskip("cryptography")
    from pramana.audit.signing import generate_keypair, sign_pack, verify_pack_signature

    private_pem, _ = generate_keypair()
    sign_pack(small_pack, private_pem)
    sig = small_pack / "signature.json"
    import json

    record = json.loads(sig.read_text())
    record["public_key"] = "NOT A VALID PEM PUBLIC KEY"
    sig.write_text(json.dumps(record))
    ok, problems = verify_pack_signature(small_pack)
    assert not ok and problems
    record["public_key"] = 12345
    sig.write_text(json.dumps(record))
    ok, problems = verify_pack_signature(small_pack)
    assert not ok and problems


# ---------------------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------------------


@pytest.fixture
def keydir(tmp_path):
    pytest.importorskip("cryptography")
    folder = tmp_path / "keys"
    folder.mkdir(mode=0o700)
    return folder


@posix_only
@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("which", ["pramana_ed25519.key", "pramana_ed25519.pub"])
def test_keygen_refuses_a_symlinked_key_path(keydir, outside, which, force):
    (keydir / which).symlink_to(outside)
    assert main(["keygen", "--out-dir", str(keydir), *(["--force"] if force else [])]) == 3
    assert outside.read_text() == MARKER


@posix_only
@pytest.mark.parametrize("which", ["pramana_ed25519.key", "pramana_ed25519.pub"])
def test_keygen_does_not_create_a_file_through_a_dangling_symlink(keydir, tmp_path, which):
    ghost = tmp_path / "ghost"
    (keydir / which).symlink_to(ghost)
    assert main(["keygen", "--out-dir", str(keydir)]) == 3
    assert not ghost.exists()


@posix_only
def test_keygen_force_replaces_a_hard_linked_key_without_writing_through(keydir, outside):
    os.link(outside, keydir / "pramana_ed25519.key")
    assert main(["keygen", "--out-dir", str(keydir), "--force"]) == 0
    assert outside.read_text() == MARKER
    assert b"PRIVATE KEY" in (keydir / "pramana_ed25519.key").read_bytes()


def test_keygen_does_not_overwrite_an_existing_public_key_without_force(keydir):
    (keydir / "pramana_ed25519.pub").write_text("existing public key\n")
    assert main(["keygen", "--out-dir", str(keydir)]) == 3
    assert (keydir / "pramana_ed25519.pub").read_text() == "existing public key\n"
    assert not (keydir / "pramana_ed25519.key").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_keygen_refuses_a_folder_other_users_can_write(keydir):
    keydir.chmod(0o777)
    assert main(["keygen", "--out-dir", str(keydir)]) == 3
    assert not (keydir / "pramana_ed25519.key").exists()


def test_keygen_leaves_no_half_pair_when_one_path_is_a_folder(keydir):
    (keydir / "pramana_ed25519.pub").mkdir()
    assert main(["keygen", "--out-dir", str(keydir), "--force"]) == 3
    assert not (keydir / "pramana_ed25519.key").exists()
    assert not [p for p in keydir.iterdir() if p.name.endswith(".tmp")]


def test_keygen_in_a_clean_folder_still_works(keydir):
    assert main(["keygen", "--out-dir", str(keydir)]) == 0
    priv, pub = keydir / "pramana_ed25519.key", keydir / "pramana_ed25519.pub"
    assert b"PRIVATE KEY" in priv.read_bytes() and b"PUBLIC KEY" in pub.read_bytes()
    if os.name == "posix":
        assert priv.stat().st_mode & 0o777 == 0o600
    assert main(["keygen", "--out-dir", str(keydir)]) == 3  # both exist now
    assert main(["keygen", "--out-dir", str(keydir), "--force"]) == 0


# ---------------------------------------------------------------------------------------
# Other writers: init, --out files, demo folder
# ---------------------------------------------------------------------------------------


@posix_only
def test_init_does_not_write_through_a_dangling_symlink(tmp_path):
    ghost = tmp_path / "ghost.yaml"
    (tmp_path / "my_audit.yaml").symlink_to(ghost)
    assert main(["init", str(tmp_path / "my_audit.yaml")]) == 3
    assert not ghost.exists()


@posix_only
def test_the_demo_refuses_a_folder_with_a_link_in_it(tmp_path, outside):
    demo = tmp_path / "demo" / "agent-traces"
    demo.mkdir(parents=True)
    (demo / "audit.yaml").symlink_to(outside)
    assert main(["demo", "agent", "--out", str(tmp_path / "demo")]) == 3
    assert outside.read_text() == MARKER


def test_safefs_rejects_paths_that_leave_the_folder(tmp_path):
    for bad in ("../x", "/etc/passwd", "a/../../x", ""):
        with pytest.raises(safefs.UnsafePathError):
            safefs.write_bytes(tmp_path, bad, b"x")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_pack_files_are_readable_by_their_owner_only(chatbot_audit, tmp_path):
    """A pack holds a system's answers, which may include personal data."""
    pack = tmp_path / "pack"
    write_outputs(chatbot_audit, pack)
    ledger = EvidenceLedger(tmp_path / "pack2")
    ledger.add_json("1-scoping", "x", {})
    written = [pack / n for n in REPORT_FILES.values()]
    written += [
        tmp_path / "pack2" / "ledger.jsonl",
        tmp_path / "pack2" / "evidence" / "1-scoping" / "x.json",
    ]
    for path in written:
        assert path.stat().st_mode & 0o077 == 0, f"{path.name} is readable by other users"
