import json

from pramana.audit.ledger import EvidenceLedger, verify_pack


def _pack(tmp_path):
    ledger = EvidenceLedger(tmp_path)
    ledger.add_json("1-scoping", "profile", {"system": "demo"})
    ledger.add_json("4-testing", "check", {"status": "pass", "value": 0.91})
    external = tmp_path.parent / f"{tmp_path.name}-model.bin"
    external.write_bytes(b"weights")
    ledger.add_external("3-artifacts", "model", external)
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
