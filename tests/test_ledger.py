import json

from pramana.audit.ledger import EvidenceLedger, verify_pack


def _pack(tmp_path):
    ledger = EvidenceLedger(tmp_path)
    ledger.add_json("1-scoping", "profile", {"system": "demo"})
    ledger.add_json("4-testing", "check", {"status": "pass", "value": 0.91})
    external = tmp_path.parent / f"{tmp_path.name}-model.bin"
    external.write_bytes(b"weights")
    ledger.add_external("3-artifacts", "model", external)
    ledger.add_text("5-reflection", "results", "results.json", '{"gate": {"decision": "BLOCK"}}')
    return ledger


def test_untouched_pack_verifies(tmp_path):
    ledger = _pack(tmp_path)
    ok, problems = verify_pack(tmp_path)
    assert ok, problems
    assert ledger.root_hash and len(ledger.root_hash) == 64


def test_external_artifacts_store_only_the_file_name(tmp_path):
    _pack(tmp_path)
    entries = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    artifact = next(e for e in entries if e["kind"] == "artifact")
    assert "/" not in artifact["path"] and "\\" not in artifact["path"]


def test_editing_evidence_is_detected(tmp_path):
    _pack(tmp_path)
    target = tmp_path / "evidence" / "4-testing" / "check.json"
    target.write_text(target.read_text().replace("pass", "fail"))
    ok, problems = verify_pack(tmp_path)
    assert not ok
    assert any("content changed" in p for p in problems)


def test_editing_a_ledger_entry_is_detected(tmp_path):
    _pack(tmp_path)
    path = tmp_path / "ledger.jsonl"
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["name"] = "renamed"
    lines[1] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    ok, problems = verify_pack(tmp_path)
    assert not ok
    assert any("modified" in p for p in problems)


def test_deleting_a_ledger_entry_is_detected(tmp_path):
    _pack(tmp_path)
    path = tmp_path / "ledger.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, problems = verify_pack(tmp_path)
    assert not ok
    assert any("chain broken" in p or "sequence gap" in p for p in problems)


# Found in the 0.7.8 review: cutting the tail off the ledger, where results.json is
# recorded, left a valid chain, and results.json could then be edited (BLOCK -> PASS).


def test_truncating_the_ledger_to_edit_results_is_detected(tmp_path):
    _pack(tmp_path)
    ledger = tmp_path / "ledger.jsonl"
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n")  # drop the results entry
    (tmp_path / "results.json").write_text('{"gate": {"decision": "PASS"}}')
    ok, problems = verify_pack(tmp_path)
    assert not ok
    assert any("unrecorded file in the pack: results.json" in p for p in problems)


def test_a_pack_without_results_is_incomplete(tmp_path):
    _pack(tmp_path)
    ledger = tmp_path / "ledger.jsonl"
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n")
    (tmp_path / "results.json").unlink()
    ok, problems = verify_pack(tmp_path)
    assert not ok and any("results.json is not recorded" in p for p in problems)


def test_a_planted_file_anywhere_in_the_pack_is_detected(tmp_path):
    _pack(tmp_path)
    (tmp_path / "summary-for-the-board.md").write_text("All controls effective.")
    ok, problems = verify_pack(tmp_path)
    assert not ok and any("summary-for-the-board.md" in p for p in problems)


def test_file_manager_metadata_and_the_signature_are_not_flagged(tmp_path):
    _pack(tmp_path)
    (tmp_path / ".DS_Store").write_bytes(b"\x00")
    (tmp_path / "signature.json").write_text("{}")
    ok, problems = verify_pack(tmp_path)
    assert ok, problems
